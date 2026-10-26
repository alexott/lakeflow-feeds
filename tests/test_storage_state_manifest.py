import io
from datetime import date

from feedkit.manifest import Manifest, manifest_path, period_committed, write_manifest
from feedkit.state import FeedState, load_state, save_state
from feedkit.storage import FilesApiStorage, PathStorage


def manifest(**over):
    base = dict(feed="tranco", fetch_id="tranco-1", status="complete", record_count=10, raw_count=10,
                source_url="u", source_version="v", transform_version="abc", started_at="s", finished_at="f",
                period="2026-10-26")
    base.update(over)
    return Manifest(**base)


def test_path_storage_roundtrip(tmp_path):
    s = PathStorage(tmp_path)
    assert s.read_text("a/b.json") is None and s.listdir("a") == [] and not s.exists("a/b.json")
    s.write_text("a/b.json", "{}")
    s.write_bytes("a/c.bin", b"\x00")
    assert s.read_text("a/b.json") == "{}" and s.exists("a/c.bin")
    assert sorted(s.listdir("a")) == ["b.json", "c.bin"]
    s.move("a/c.bin", "z/c.bin")
    assert not s.exists("a/c.bin") and s.exists("z/c.bin")


def test_state_default_and_roundtrip(tmp_path):
    s = PathStorage(tmp_path)
    assert load_state(s, "tor") == FeedState()
    st = FeedState(etag='"x"', last_record_count=1200, last_period="2026-10-25")
    save_state(s, "tor", st)
    assert load_state(s, "tor") == st
    assert (tmp_path / "state" / "tor.json").exists()


def test_manifest_paths():
    assert manifest_path(manifest()) == "manifests/tranco/2026-10-26/tranco-1.json"
    assert manifest_path(manifest(period=None)) == "manifests/tranco/tranco-1.json"


def test_period_committed_only_for_complete_manifests(tmp_path):
    s = PathStorage(tmp_path)
    day = date(2026, 10, 26)
    assert not period_committed(s, "tranco", day)
    write_manifest(s, manifest(status="failed"))
    assert not period_committed(s, "tranco", day)
    write_manifest(s, manifest(fetch_id="tranco-2"))
    assert period_committed(s, "tranco", day)
    assert not period_committed(s, "tranco", date(2026, 10, 25))


class FakeFiles:
    """Minimal stand-in for WorkspaceClient().files."""

    def __init__(self):
        self.data = {}

    def upload(self, file_path, contents, overwrite=False):
        self.data[file_path] = contents.read()

    def download(self, file_path):
        if file_path not in self.data:
            from databricks.sdk.errors import NotFound
            raise NotFound("missing")
        return type("R", (), {"contents": io.BytesIO(self.data[file_path])})()

    def get_metadata(self, file_path):
        if file_path not in self.data:
            from databricks.sdk.errors import NotFound
            raise NotFound("missing")

    def list_directory_contents(self, directory_path):
        prefix = directory_path.rstrip("/") + "/"
        names = {p[len(prefix):].split("/")[0] for p in self.data if p.startswith(prefix)}
        if not names:
            from databricks.sdk.errors import NotFound
            raise NotFound("missing")
        return [type("E", (), {"name": n})() for n in sorted(names)]

    def delete(self, file_path):
        del self.data[file_path]


def test_files_api_storage_roundtrip():
    client = type("C", (), {"files": FakeFiles()})()
    s = FilesApiStorage(client, "/Volumes/cybersecurity/feeds")
    assert s.read_text("state/x.json") is None and s.listdir("state") == []
    s.write_text("state/x.json", "{}")
    assert s.read_text("state/x.json") == "{}" and s.exists("state/x.json")
    assert s.listdir("state") == ["x.json"]
    s.move("state/x.json", "state/y.json")
    assert s.listdir("state") == ["y.json"]
    assert "/Volumes/cybersecurity/feeds/state/y.json" in client.files.data
