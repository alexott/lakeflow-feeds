from feedkit.probe import run_checks


def test_run_checks_reports_values_and_errors():
    def boom():
        raise RuntimeError("no spark")

    report = run_checks({"python": lambda: "3.12", "spark": boom})
    assert report["python"] == {"ok": True, "value": "3.12"}
    assert report["spark"] == {"ok": False, "error": "RuntimeError: no spark"}


def test_write_report_writes_json_file(tmp_path):
    import json
    from feedkit.probe import write_report
    path = write_report({"python": {"ok": True, "value": "3.12"}}, str(tmp_path))
    assert path.startswith(str(tmp_path)) and path.endswith(".json")
    assert json.loads(open(path).read())["python"]["value"] == "3.12"
