#!/usr/bin/env python3
import argparse
import csv
import json
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

DOWNLOAD_API = "https://cloud-api.yandex.net/v1/disk/resources/download"
ATTEMPTS = 3
RETRYABLE_HTTP = {429, 500, 502, 503, 504}
SETTLED = {"OK", "EMPTY", "MISSING"}
FIELDS = ["status", "path", "size", "md5", "reason", "checked"]
PROGRESS_SECONDS = 60


class Unreadable(Exception):
    pass


class Transient(Exception):
    pass


class Missing(Exception):
    pass


def access_token(remote):
    # rclone refreshes an expired token in its config when it next talks to the remote.
    subprocess.run(["rclone", "about", f"{remote}:"], check=True, capture_output=True)
    dump = subprocess.run(["rclone", "config", "dump"], check=True, capture_output=True, text=True).stdout
    return json.loads(json.loads(dump)[remote]["token"])["access_token"]


def load_listing(listing, remote):
    if not listing.exists():
        print(f"Listing {remote}: into {listing} ...", file=sys.stderr, flush=True)
        partial = listing.with_suffix(".partial")
        with partial.open("w") as out:
            subprocess.run(
                ["rclone", "lsjson", "-R", "--files-only", "--hash", "--no-mimetype", "--checkers", "16", f"{remote}:"],
                check=True, stdout=out)
        partial.rename(listing)
    return json.loads(listing.read_text())


def latest_status(results):
    if not results.exists():
        return {}
    with results.open(newline="") as rows:
        return {row["path"]: row for row in csv.DictReader(rows)}


def download_link(token, path):
    query = urllib.parse.urlencode({"path": "disk:/" + path})
    request = urllib.request.Request(f"{DOWNLOAD_API}?{query}", headers={"Authorization": "OAuth " + token})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)["href"]
    except urllib.error.HTTPError as error:
        reason = f"link: http {error.code} {error.read()[:200].decode(errors='replace')}"
        if error.code == 404:
            raise Missing(reason)
        if error.code in RETRYABLE_HTTP:
            raise Transient(reason)
        raise Unreadable(reason)
    except OSError as error:
        raise Transient(f"link: {error}")


def read_first_byte(href):
    result = subprocess.run(
        ["curl", "-sS", "-L", "-o", "/dev/null", "--connect-timeout", "20", "--max-time", "60",
         # Aborts instead of downloading the whole file when the server ignores the range.
         "--max-filesize", "1",
         "-r", "0-0", "-w", "%{http_code} %{size_download}", href],
        capture_output=True, text=True)
    code, size = (result.stdout.split() + ["000", "0"])[:2]
    if result.returncode == 0 and code in ("200", "206") and size == "1":
        return
    reason = f"first byte: http {code}, curl exit {result.returncode}, {size} bytes"
    # Storage that answers 206 and closes the connection empty does so again on every retry.
    if code == "206" and result.returncode == 18:
        raise Unreadable(reason)
    raise Transient(reason)


def probe(token, path, size):
    if size == 0:
        return "EMPTY", ""
    reason = ""
    for attempt in range(ATTEMPTS):
        if attempt:
            time.sleep(5 * attempt)
        try:
            read_first_byte(download_link(token, path))
            return "OK", ""
        except Missing as error:
            return "MISSING", str(error)
        except Unreadable as error:
            return "UNREADABLE", str(error)
        except Transient as error:
            reason = str(error)
    return "ERROR", reason


def top_folder(path):
    return path.split("/")[0] if "/" in path else "(root)"


def write_report(entries, results, directory):
    status = latest_status(results)
    counts = Counter()
    folders = defaultdict(Counter)
    folder_bytes = defaultdict(int)
    unreadable = []
    for entry in entries:
        row = status.get(entry["Path"])
        state = row["status"] if row else "NOT CHECKED"
        counts[state] += 1
        folders[top_folder(entry["Path"])][state] += 1
        if state == "UNREADABLE":
            unreadable.append(row)
            folder_bytes[top_folder(entry["Path"])] += entry["Size"]
    unreadable.sort(key=lambda row: row["path"])
    with (directory / "unavailable.txt").open("w") as out:
        for row in unreadable:
            out.write(f"{row['size']}\t{row['path']}\n")

    lines = [f"Files: {len(entries)}; " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())),
             f"Unreadable: {len(unreadable)} files, {sum(folder_bytes.values()) / 2**30:.2f} GiB",
             "",
             f"{'folder':40} {'files':>8} {'checked':>8} {'unreadable':>10} {'GiB':>8}"]
    for folder, folder_counts in sorted(folders.items(), key=lambda item: -item[1]["UNREADABLE"]):
        files = sum(folder_counts.values())
        checked = files - folder_counts["NOT CHECKED"]
        lines.append(f"{folder[:40]:40} {files:8} {checked:8} {folder_counts['UNREADABLE']:10} "
                     f"{folder_bytes[folder] / 2**30:8.2f}")
    summary = "\n".join(lines) + "\n"
    (directory / "summary.txt").write_text(summary)
    print("\n" + summary, file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Reads the first byte of every file of a Yandex Disk rclone remote and lists the files "
                    "whose content storage cannot return. A rerun probes again every file not found readable.")
    parser.add_argument("--remote", default="yadisk", help="name of the rclone remote of type yandex")
    parser.add_argument("--dir", type=Path, default=Path.cwd(),
                        help="directory holding listing.json, results.csv, summary.txt and unavailable.txt")
    parser.add_argument("--workers", type=int, default=64)
    parser.add_argument("--limit", type=int, help="probe at most this many files")
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, signal.default_int_handler)

    entries = load_listing(args.dir / "listing.json", args.remote)
    results = args.dir / "results.csv"
    status = latest_status(results)
    todo = [e for e in entries if status.get(e["Path"], {}).get("status") not in SETTLED]
    folder_files = Counter(top_folder(e["Path"]) for e in entries)
    todo.sort(key=lambda e: folder_files[top_folder(e["Path"])])
    if args.limit:
        todo = todo[:args.limit]
    print(f"Files: {len(entries)}, to probe: {len(todo)}, workers: {args.workers}", file=sys.stderr, flush=True)

    token = access_token(args.remote)
    new_file = not results.exists()
    counts = Counter()
    started = last_progress = time.time()
    pool = ThreadPoolExecutor(args.workers)
    try:
        with results.open("a", newline="") as out:
            writer = csv.writer(out)
            if new_file:
                writer.writerow(FIELDS)
            futures = {pool.submit(probe, token, e["Path"], e["Size"]): e for e in todo}
            for done, future in enumerate(as_completed(futures), 1):
                entry = futures[future]
                state, reason = future.result()
                counts[state] += 1
                writer.writerow([state, entry["Path"], entry["Size"], entry.get("Hashes", {}).get("md5", ""),
                                 reason, time.strftime("%Y-%m-%dT%H:%M:%S")])
                out.flush()
                now = time.time()
                if now - last_progress >= PROGRESS_SECONDS or done == len(todo):
                    last_progress = now
                    rate = done / (now - started)
                    eta = (len(todo) - done) / rate
                    print(f"{done}/{len(todo)} " + " ".join(f"{k}={v}" for k, v in sorted(counts.items())) +
                          f" {rate:.1f} files/s, ETA {eta / 60:.0f} min", file=sys.stderr, flush=True)
    except KeyboardInterrupt:
        print("\nInterrupted; a rerun continues from here.", file=sys.stderr)
    pool.shutdown(wait=False, cancel_futures=True)
    write_report(entries, results, args.dir)


if __name__ == "__main__":
    main()
