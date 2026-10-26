from feedkit.probe import run_checks


def test_run_checks_reports_values_and_errors():
    def boom():
        raise RuntimeError("no spark")

    report = run_checks({"python": lambda: "3.12", "spark": boom})
    assert report["python"] == {"ok": True, "value": "3.12"}
    assert report["spark"] == {"ok": False, "error": "RuntimeError: no spark"}
