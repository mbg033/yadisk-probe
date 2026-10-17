import importlib.util
import io
import json
import stat
import subprocess
import tempfile
import unittest
import urllib.error
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parent.parent / "yadisk-probe.py"
spec = importlib.util.spec_from_file_location("yadisk_probe", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def stored_token(expires_in):
    return {
        "client_id": "client",
        "client_secret": "secret",
        "access_token": "old-access",
        "refresh_token": "old-refresh",
        "expiry": (datetime.now(timezone.utc) + expires_in).isoformat(timespec="seconds"),
    }


class TokenFileTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.token_file = Path(directory.name) / "config" / "token.json"

    def test_token_far_from_expiry_is_used_as_stored(self):
        probe.save_token(self.token_file, stored_token(timedelta(days=30)))
        with mock.patch.object(probe, "send", side_effect=AssertionError("no request expected")):
            token = probe.load_token(self.token_file)
        self.assertEqual(token["access_token"], "old-access")

    def test_token_near_expiry_is_refreshed_and_stored(self):
        probe.save_token(self.token_file, stored_token(timedelta(hours=1)))
        fresh = {"access_token": "new-access", "refresh_token": "new-refresh", "expires_in": 31536000}
        with mock.patch.object(probe, "send", return_value=fresh) as send:
            token = probe.load_token(self.token_file)
        form = form_of(send.call_args.args[0])
        self.assertEqual(form["grant_type"], "refresh_token")
        self.assertEqual(form["refresh_token"], "old-refresh")
        self.assertEqual(token["access_token"], "new-access")
        self.assertEqual(json.loads(self.token_file.read_text())["refresh_token"], "new-refresh")
        self.assertGreater(datetime.fromisoformat(token["expiry"]), datetime.now(timezone.utc) + timedelta(days=300))

    def test_token_file_is_readable_by_owner_only(self):
        probe.save_token(self.token_file, stored_token(timedelta(days=30)))
        self.assertEqual(stat.S_IMODE(self.token_file.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.token_file.parent.stat().st_mode), 0o700)


def form_of(request):
    return dict(urllib.parse.parse_qsl(request.data.decode()))


def http_error(code, body):
    return urllib.error.HTTPError("https://example.invalid", code, "error", {}, io.BytesIO(json.dumps(body).encode()))


class CodeExchangeTest(unittest.TestCase):
    def test_code_is_exchanged_for_token_carrying_client_credentials(self):
        fresh = {"access_token": "access", "refresh_token": "refresh", "expires_in": 31536000}
        with mock.patch.object(probe, "send", return_value=fresh) as send:
            token = probe.exchange_code("client", "secret", "1234567")
        self.assertEqual(form_of(send.call_args.args[0]),
                         {"grant_type": "authorization_code", "code": "1234567",
                          "client_id": "client", "client_secret": "secret"})
        self.assertEqual({k: token[k] for k in ("client_id", "client_secret", "access_token", "refresh_token")},
                         {"client_id": "client", "client_secret": "secret",
                          "access_token": "access", "refresh_token": "refresh"})
        self.assertGreater(datetime.fromisoformat(token["expiry"]), datetime.now(timezone.utc) + timedelta(days=300))

    def test_refused_code_stops_with_yandex_description(self):
        refusal = http_error(400, {"error": "invalid_grant", "error_description": "Code has expired"})
        with mock.patch.object(probe, "send", side_effect=refusal):
            with self.assertRaisesRegex(SystemExit, "Code has expired"):
                probe.exchange_code("client", "secret", "1234567")


def file_item(path, size):
    return {"type": "file", "path": "disk:/" + path, "size": size, "md5": "md5-" + path, "sha256": "sha-" + path}


def dir_item(path):
    return {"type": "dir", "path": "disk:/" + path}


class FakeDisk:
    def __init__(self, tree, page_size, missing=()):
        self.tree, self.page_size, self.missing = tree, page_size, set(missing)

    def __call__(self, request):
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(request.full_url).query))
        directory = query["path"].removeprefix("disk:/")
        if directory in self.missing:
            raise http_error(404, {"error": "DiskNotFoundError"})
        items = self.tree[directory]
        offset = int(query.get("offset", 0))
        return {"_embedded": {"items": items[offset:offset + self.page_size], "total": len(items)}}


class ApiListingTest(unittest.TestCase):
    def listed(self, disk):
        with mock.patch.object(probe, "send", disk), mock.patch.object(probe, "LIST_PAGE", disk.page_size):
            entries = probe.list_with_api("access")
        return sorted((e["Path"], e["Size"], e["Hashes"]["md5"]) for e in entries)

    def test_every_file_of_nested_paged_directories_is_listed(self):
        disk = FakeDisk({
            "": [dir_item("A"), file_item("root.txt", 5)],
            "A": [file_item("A/a1", 1), file_item("A/a2", 2), dir_item("A/B")],
            "A/B": [file_item("A/B/b1", 3)],
        }, page_size=2)
        self.assertEqual(self.listed(disk), [("A/B/b1", 3, "md5-A/B/b1"), ("A/a1", 1, "md5-A/a1"),
                                             ("A/a2", 2, "md5-A/a2"), ("root.txt", 5, "md5-root.txt")])

    def test_directory_removed_during_listing_is_skipped(self):
        disk = FakeDisk({"": [dir_item("gone"), file_item("kept", 1)]}, page_size=10, missing={"gone"})
        self.assertEqual(self.listed(disk), [("kept", 1, "md5-kept")])

    def test_empty_disk_lists_nothing(self):
        self.assertEqual(self.listed(FakeDisk({"": []}, page_size=10)), [])


class RcloneListingTest(unittest.TestCase):
    def test_rclone_lists_disk_with_token_passed_in_environment(self):
        listing = [{"Path": "A/a1", "Size": 1, "Hashes": {"md5": "m"}}]
        completed = subprocess.CompletedProcess([], 0, stdout=json.dumps(listing))
        with mock.patch.object(probe.subprocess, "run", return_value=completed) as run:
            entries = probe.list_with_rclone(stored_token(timedelta(days=30)))
        command, environment = run.call_args.args[0], run.call_args.kwargs["env"]
        self.assertEqual(command[0], "rclone")
        self.assertEqual(command[-1], ":yandex:")
        self.assertEqual(json.loads(environment["RCLONE_YANDEX_TOKEN"])["access_token"], "old-access")
        self.assertEqual(json.loads(environment["RCLONE_YANDEX_TOKEN"])["token_type"], "OAuth")
        self.assertEqual(environment["RCLONE_YANDEX_CLIENT_ID"], "client")
        self.assertEqual(environment["RCLONE_YANDEX_CLIENT_SECRET"], "secret")
        self.assertEqual(entries, listing)

    def test_names_encoded_by_rclone_are_returned_as_stored_on_disk(self):
        encoded = ["dir/book␊.epub", "tab␉and del␡", "literal ‛␊ sign", "plain"]
        listing = [{"Path": path, "Size": 1, "Hashes": {"md5": "m"}} for path in encoded]
        completed = subprocess.CompletedProcess([], 0, stdout=json.dumps(listing))
        with mock.patch.object(probe.subprocess, "run", return_value=completed):
            entries = probe.list_with_rclone(stored_token(timedelta(days=30)))
        self.assertEqual([e["Path"] for e in entries],
                         ["dir/book\n.epub", "tab\tand del\x7f", "literal ␊ sign", "plain"])


def curl_result(http_code, size, exit_code):
    return subprocess.CompletedProcess([], exit_code, stdout=f"{http_code} {size}", stderr="")


class ProbeTest(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(probe, "RETRY_PAUSE", 0)
        patcher.start()
        self.addCleanup(patcher.stop)

    def status(self, send, curl=None):
        with mock.patch.object(probe, "send", send), \
                mock.patch.object(probe.subprocess, "run", return_value=curl):
            return probe.probe("access", "dir/file", 10)[0]

    def test_file_whose_first_byte_is_read_is_ok(self):
        self.assertEqual(self.status(mock.Mock(return_value={"href": "h"}), curl_result(206, 1, 0)), "OK")

    def test_storage_closing_connection_without_data_marks_file_unreadable(self):
        self.assertEqual(self.status(mock.Mock(return_value={"href": "h"}), curl_result(206, 0, 18)), "UNREADABLE")

    def test_error_persisting_through_retries_marks_file_error(self):
        send = mock.Mock(side_effect=http_error(503, {}))
        self.assertEqual(self.status(send), "ERROR")
        self.assertEqual(send.call_count, probe.ATTEMPTS)

    def test_file_deleted_since_listing_is_missing(self):
        self.assertEqual(self.status(mock.Mock(side_effect=http_error(404, {}))), "MISSING")

    def test_rejected_token_stops_probing_instead_of_marking_file(self):
        with self.assertRaises(probe.Unauthorized):
            self.status(mock.Mock(side_effect=http_error(401, {"error": "UnauthorizedError"})))


class CommandLineTest(unittest.TestCase):
    def test_rclone_lists_files_by_default(self):
        self.assertEqual(probe.parse_arguments([]).lister, "rclone")

    def test_api_can_list_files_instead_of_rclone(self):
        self.assertEqual(probe.parse_arguments(["--lister", "api"]).lister, "api")

    def test_unknown_lister_is_rejected(self):
        with mock.patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit):
            probe.parse_arguments(["--lister", "webdav"])

    def test_token_file_defaults_to_user_config_directory(self):
        with mock.patch.dict("os.environ", {"XDG_CONFIG_HOME": "/config-home"}):
            token_file = probe.parse_arguments([]).token_file
        self.assertEqual(token_file, Path("/config-home/yadisk-probe/token.json"))


class ListingFileTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.listing = Path(directory.name) / "listing.json"
        self.entries = [{"Path": "a", "Size": 1, "Hashes": {"md5": "m"}}]

    def test_chosen_lister_builds_listing_once(self):
        token = stored_token(timedelta(days=30))
        with mock.patch.object(probe, "list_with_api", return_value=self.entries) as api, \
                mock.patch.object(probe, "list_with_rclone", side_effect=AssertionError("rclone not chosen")):
            first = probe.load_listing(self.listing, token, "api")
            second = probe.load_listing(self.listing, token, "api")
        api.assert_called_once_with("old-access")
        self.assertEqual(first, self.entries)
        self.assertEqual(second, self.entries)


if __name__ == "__main__":
    unittest.main()
