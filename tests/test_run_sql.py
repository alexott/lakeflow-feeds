import pytest

from run_sql import render


def test_render_substitutes_and_splits():
    sql = "-- comment\nCREATE SCHEMA {{catalog}}.{{schema}};\n\nSELECT ';' AS x\nFROM t;\n"
    assert render(sql, {"catalog": "c", "schema": "s"}) == ["CREATE SCHEMA c.s", "SELECT ';' AS x\nFROM t"]


def test_render_missing_param():
    with pytest.raises(KeyError, match="schema"):
        render("SELECT {{schema}};", {})
