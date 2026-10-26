import pytest

from cost_by_feed import values_list


def test_values_list_quotes_and_escapes():
    assert values_list([("a-1", "records"), ("b-2", "it's")]) == "('a-1', 'records'), ('b-2', 'it''s')"


def test_values_list_rejects_empty():
    with pytest.raises(ValueError):
        values_list([])
