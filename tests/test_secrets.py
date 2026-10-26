import pytest

from feedkit.secrets import SecretError, has_refs, substitute, substitute_all


def lookup(scope, key):
    return {("abusech", "auth_key"): "k123", ("feeds", "sp_client_id"): "cid"}[(scope, key)]


def test_substitute_references_in_a_string():
    assert substitute("{{secrets/abusech/auth_key}}", lookup) == "k123"
    assert substitute("Bearer {{secrets/abusech/auth_key}}!", lookup) == "Bearer k123!"
    assert substitute("no refs", lookup) == "no refs"


def test_substitute_all_walks_dicts_and_lists_and_keeps_other_types():
    obj = {"h": {"Auth-Key": "{{secrets/abusech/auth_key}}"}, "l": ["{{secrets/feeds/sp_client_id}}", 7], "n": None}
    assert substitute_all(obj, lookup) == {"h": {"Auth-Key": "k123"}, "l": ["cid", 7], "n": None}


def test_reference_without_lookup_raises():
    with pytest.raises(SecretError, match="abusech/auth_key"):
        substitute("{{secrets/abusech/auth_key}}", None)


def test_has_refs():
    assert has_refs({"a": ["x", "{{secrets/s/k}}"]}) and not has_refs({"a": "x"})
