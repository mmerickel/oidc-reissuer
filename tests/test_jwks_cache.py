import logging

from oidc_token_proxy.jwks_cache import make_jwks_cache_from_path


def test_load_missing_file(caplog, tmp_path):
    caplog.set_level(level=logging.WARNING, logger="oidc_token_proxy.jwks_cache")
    cache = make_jwks_cache_from_path(tmp_path / "missing.json")
    assert len(cache.value["keys"]) == 0
    assert "could not find jwks file at path" in caplog.text
