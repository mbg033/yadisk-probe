#!/usr/bin/env python3
import argparse
import csv
import getpass
import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from collections import Counter, defaultdict
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timedelta, timezone
from pathlib import Path

DISK_API = "https://cloud-api.yandex.net/v1/disk"
OAUTH_AUTHORIZE_URL = "https://oauth.yandex.ru/authorize"
OAUTH_TOKEN_URL = "https://oauth.yandex.ru/token"
REFRESH_MARGIN = timedelta(days=1)
LIST_PAGE = 1000
LIST_WORKERS = 16
LIST_FIELDS = ("_embedded.total,_embedded.items.type,_embedded.items.path,"
               "_embedded.items.size,_embedded.items.md5,_embedded.items.sha256")
RCLONE_CONTROL_PICTURE_BASE = "\u2400"
RCLONE_DELETE_PICTURE = "\u2421"
RCLONE_QUOTE = "\u201b"
ATTEMPTS = 3
RETRY_PAUSE = 5
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


class Unauthorized(Exception):
    pass


def send(request):
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def expiry_after(seconds):
    return (datetime.now(timezone.utc) + timedelta(seconds=int(seconds))).isoformat(timespec="seconds")


def save_token(token_file, token):
    token_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    partial = token_file.with_suffix(".partial")
    descriptor = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w") as out:
        json.dump(token, out, indent=1)
    partial.replace(token_file)


def request_token(form):
    try:
        return send(urllib.request.Request(OAUTH_TOKEN_URL, data=urllib.parse.urlencode(form).encode()))
    except urllib.error.HTTPError as error:
        refusal = json.loads(error.read() or b"{}")
        sys.exit(f"Yandex OAuth refused: {refusal.get('error')} - {refusal.get('error_description')}")


def exchange_code(client_id, client_secret, code):
    fresh = request_token({"grant_type": "authorization_code", "code": code,
                           "client_id": client_id, "client_secret": client_secret})
    return {"client_id": client_id, "client_secret": client_secret,
            "access_token": fresh["access_token"], "refresh_token": fresh["refresh_token"],
            "expiry": expiry_after(fresh["expires_in"])}


def load_token(token_file):
    token = json.loads(token_file.read_text())
    if datetime.fromisoformat(token["expiry"]) - datetime.now(timezone.utc) < REFRESH_MARGIN:
        fresh = request_token({"grant_type": "refresh_token", "refresh_token": token["refresh_token"],
                               "client_id": token["client_id"], "client_secret": token["client_secret"]})
        token = {**token, "access_token": fresh["access_token"],
                 "refresh_token": fresh.get("refresh_token", token["refresh_token"]),
                 "expiry": expiry_after(fresh["expires_in"])}
        save_token(token_file, token)
    return token


def api_get(access_token, endpoint, params):
    request = urllib.request.Request(f"{DISK_API}{endpoint}?{urllib.parse.urlencode(params)}",
                                     headers={"Authorization": "OAuth " + access_token})
    try:
        return send(request)
    except urllib.error.HTTPError as error:
        reason = f"{endpoint}: http {error.code} {error.read()[:200].decode(errors='replace')}"
        if error.code in (401, 403):
            raise Unauthorized(reason)
        if error.code == 404:
            raise Missing(reason)
        if error.code in RETRYABLE_HTTP:
            raise Transient(reason)
        raise Unreadable(reason)
    except OSError as error:
        raise Transient(f"{endpoint}: {error}")


def with_retries(call, *args):
    for attempt in range(ATTEMPTS):
        if attempt:
            time.sleep(RETRY_PAUSE * attempt)
        try:
            return call(*args)
        except Transient as error:
            failure = error
    raise failure


def list_directory(access_token, directory):
    files, subdirectories = [], []
    offset = 0
    while True:
        params = {"path": "disk:/" + directory, "limit": LIST_PAGE, "offset": offset, "fields": LIST_FIELDS}
        try:
            page = with_retries(api_get, access_token, "/resources", params)["_embedded"]
        except Missing:
            return files, subdirectories
        for item in page["items"]:
            path = item["path"].removeprefix("disk:/")
            if item["type"] == "dir":
                subdirectories.append(path)
            else:
                files.append({"Path": path, "Size": item["size"],
                              "Hashes": {"md5": item.get("md5", ""), "sha256": item.get("sha256", "")}})
        offset += len(page["items"])
        if not page["items"] or offset >= page["total"]:
            return files, subdirectories


def list_with_api(access_token):
    entries = []
    directories = 0
    started = last_progress = time.monotonic()
    with ThreadPoolExecutor(LIST_WORKERS) as pool:
        pending = {pool.submit(list_directory, access_token, "")}
        while pending:
            timeout = max(0, PROGRESS_SECONDS - (time.monotonic() - last_progress))
            done, pending = wait(pending, timeout=timeout, return_when=FIRST_COMPLETED)
            for future in done:
                files, subdirectories = future.result()
                directories += 1
                entries.extend(files)
                pending |= {pool.submit(list_directory, access_token, path) for path in subdirectories}
            now = time.monotonic()
            if now - last_progress >= PROGRESS_SECONDS or not pending:
                print(f"Listing: files={len(entries)}, folders done={directories}, pending={len(pending)}, "
                      f"elapsed {(now - started) / 60:.1f} min", file=sys.stderr, flush=True)
                last_progress = now
    return entries


def disk_name(rclone_name):
    name = []
    characters = iter(rclone_name)
    for character in characters:
        if character == RCLONE_QUOTE:
            name.append(next(characters, ""))
        elif RCLONE_CONTROL_PICTURE_BASE <= character < chr(ord(RCLONE_CONTROL_PICTURE_BASE) + 32):
            name.append(chr(ord(character) - ord(RCLONE_CONTROL_PICTURE_BASE)))
        elif character == RCLONE_DELETE_PICTURE:
            name.append("\x7f")
        else:
            name.append(character)
    return "".join(name)


def list_with_rclone(token):
    rclone_token = {"access_token": token["access_token"], "token_type": "OAuth",
                    "refresh_token": token["refresh_token"], "expiry": token["expiry"]}
    environment = {**os.environ,
                   "RCLONE_YANDEX_TOKEN": json.dumps(rclone_token),
                   "RCLONE_YANDEX_CLIENT_ID": token["client_id"],
                   "RCLONE_YANDEX_CLIENT_SECRET": token["client_secret"]}
    result = subprocess.run(
        ["rclone", "lsjson", "-R", "--files-only", "--hash", "--no-mimetype", "--checkers", "16", ":yandex:"],
        check=True, stdout=subprocess.PIPE, text=True, env=environment)
    entries = json.loads(result.stdout)
    for entry in entries:
        entry["Path"] = disk_name(entry["Path"])
    return entries


def load_listing(listing, token, lister):
    if not listing.exists():
        print(f"Listing the disk with {lister} into {listing} ...", file=sys.stderr, flush=True)
        entries = list_with_rclone(token) if lister == "rclone" else list_with_api(token["access_token"])
        partial = listing.with_suffix(".partial")
        partial.write_text(json.dumps(entries))
        partial.replace(listing)
    else:
        print(f"Loading saved listing from {listing} ...", file=sys.stderr, flush=True)
    return json.loads(listing.read_text())


def login(token_file):
    client_id = input("ClientID: ").strip()
    client_secret = getpass.getpass("Client secret: ").strip()
    url = OAUTH_AUTHORIZE_URL + "?" + urllib.parse.urlencode({"response_type": "code", "client_id": client_id})
    print(f"Open the link, press Allow and copy the confirmation code from the page:\n  {url}")
    webbrowser.open(url)
    token = exchange_code(client_id, client_secret, input("Confirmation code: ").strip())
    save_token(token_file, token)
    print(f"Token saved to {token_file}")
    try:
        root = api_get(token["access_token"], "/resources", {"path": "disk:/", "limit": 5, "fields": "_embedded.items.name"})
    except (Unauthorized, Unreadable, Transient) as error:
        sys.exit(f"Listing the disk with the new token failed: {error}")
    print("First entries of the disk: " + ", ".join(item["name"] for item in root["_embedded"]["items"]))


def latest_status(results):
    return result_history(results)[0]


def result_history(results):
    status, previously_unreadable = {}, set()
    if not results.exists():
        return status, previously_unreadable
    with results.open(newline="") as rows:
        for row in csv.DictReader(rows):
            status[row["path"]] = row
            if row["status"] == "UNREADABLE":
                previously_unreadable.add(row["path"])
    return status, previously_unreadable


def download_link(access_token, path):
    return api_get(access_token, "/resources/download", {"path": "disk:/" + path})["href"]


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


def read_file_start(access_token, path):
    read_first_byte(download_link(access_token, path))


def probe(access_token, path, size):
    if size == 0:
        return "EMPTY", ""
    try:
        with_retries(read_file_start, access_token, path)
        return "OK", ""
    except Missing as error:
        return "MISSING", str(error)
    except Unreadable as error:
        return "UNREADABLE", str(error)
    except Transient as error:
        return "ERROR", str(error)


def top_folder(path):
    return path.split("/")[0] if "/" in path else "(root)"


def write_report(entries, results, directory):
    status, previously_unreadable = result_history(results)
    counts = Counter()
    folders = defaultdict(Counter)
    folder_bytes = defaultdict(int)
    unreadable = []
    recovered = []
    for entry in entries:
        row = status.get(entry["Path"])
        state = row["status"] if row else "NOT CHECKED"
        counts[state] += 1
        folders[top_folder(entry["Path"])][state] += 1
        if state == "UNREADABLE":
            unreadable.append(row)
            folder_bytes[top_folder(entry["Path"])] += entry["Size"]
        elif state == "OK" and entry["Path"] in previously_unreadable:
            recovered.append(row)
    unreadable.sort(key=lambda row: row["path"])
    with (directory / "unavailable.txt").open("w") as out:
        for row in unreadable:
            out.write(f"{row['size']}\t{row['path']}\n")
    recovered.sort(key=lambda row: row["path"])
    with (directory / "recovered.txt").open("w") as out:
        for row in recovered:
            out.write(f"{row['size']}\t{row['path']}\n")

    lines = [f"Files: {len(entries)}; " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())),
             f"Unreadable: {len(unreadable)} files, {sum(folder_bytes.values()) / 2**30:.2f} GiB",
             f"Recovered (UNREADABLE -> OK): {len(recovered)} files; list: {directory / 'recovered.txt'}",
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


def default_token_file():
    config_home = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(config_home) / "yadisk-probe" / "token.json"


def parse_arguments(argv):
    parser = argparse.ArgumentParser(
        description="Reads the first byte of every file of a Yandex Disk and lists the files whose content "
                    "storage cannot return. A rerun probes again every file not found readable.")
    parser.add_argument("--login", action="store_true",
                        help="obtain an OAuth token, store it in the token file and exit")
    parser.add_argument("--token-file", type=Path, default=default_token_file(),
                        help="file holding the OAuth token and the credentials of the OAuth app")
    parser.add_argument("--lister", choices=("rclone", "api"), default="rclone",
                        help="what lists the files of the disk: rclone, or the REST API of Yandex Disk")
    parser.add_argument("--dir", type=Path, default=Path.cwd(),
                        help="directory holding listing.json, results.csv, summary.txt, unavailable.txt and recovered.txt")
    parser.add_argument("--workers", type=int, default=64)
    parser.add_argument("--limit", type=int, help="probe at most this many files")
    return parser.parse_args(argv)


def main():
    args = parse_arguments(sys.argv[1:])
    if args.login:
        login(args.token_file)
        return
    if not args.token_file.exists():
        sys.exit(f"No token file {args.token_file}; obtain a token with --login first.")
    signal.signal(signal.SIGTERM, signal.default_int_handler)

    args.dir = args.dir.resolve()
    args.dir.mkdir(parents=True, exist_ok=True)
    print(f"Reports directory: {args.dir}", file=sys.stderr, flush=True)
    token = load_token(args.token_file)
    entries = load_listing(args.dir / "listing.json", token, args.lister)
    results = args.dir / "results.csv"
    status = latest_status(results)
    todo = [e for e in entries if status.get(e["Path"], {}).get("status") not in SETTLED]
    folder_files = Counter(top_folder(e["Path"]) for e in entries)
    todo.sort(key=lambda e: folder_files[top_folder(e["Path"])])
    if args.limit:
        todo = todo[:args.limit]
    print(f"Files: {len(entries)}, to probe: {len(todo)}, workers: {args.workers}", file=sys.stderr, flush=True)

    new_file = not results.exists()
    counts = Counter()
    started = last_progress = time.monotonic()
    stop = None
    pool = ThreadPoolExecutor(args.workers)
    try:
        with results.open("a", newline="") as out:
            writer = csv.writer(out)
            if new_file:
                writer.writerow(FIELDS)
            futures = {pool.submit(probe, token["access_token"], e["Path"], e["Size"]): e for e in todo}
            pending = set(futures)
            checked = 0
            while pending:
                timeout = max(0, PROGRESS_SECONDS - (time.monotonic() - last_progress))
                done, pending = wait(pending, timeout=timeout, return_when=FIRST_COMPLETED)
                for future in done:
                    entry = futures[future]
                    state, reason = future.result()
                    counts[state] += 1
                    checked += 1
                    writer.writerow([state, entry["Path"], entry["Size"], entry.get("Hashes", {}).get("md5", ""),
                                     reason, time.strftime("%Y-%m-%dT%H:%M:%S")])
                    out.flush()
                now = time.monotonic()
                if now - last_progress >= PROGRESS_SECONDS or not pending:
                    last_progress = now
                    rate = checked / max(now - started, 1e-9)
                    eta = f"{(len(todo) - checked) / rate / 60:.0f} min" if rate else "unknown"
                    print(f"{checked}/{len(todo)} " + " ".join(f"{k}={v}" for k, v in sorted(counts.items())) +
                          f" {rate:.1f} files/s, ETA {eta}", file=sys.stderr, flush=True)
    except KeyboardInterrupt:
        print("\nInterrupted; a rerun continues from here.", file=sys.stderr)
    except Unauthorized as error:
        stop = f"Yandex rejected the token ({error}); obtain a new one with --login."
    pool.shutdown(wait=False, cancel_futures=True)
    write_report(entries, results, args.dir)
    if stop:
        sys.exit(stop)


if __name__ == "__main__":
    main()
