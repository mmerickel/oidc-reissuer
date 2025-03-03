import pytest


def test_invalid_signing_key_config(mock_env):
    mock_env.app_settings["signing_key_ids"] = {"ES256": "invalid kid"}
    with pytest.raises(ValueError):
        mock_env.make_testapp()


def test_mismatch_signing_key_config(mock_env):
    mock_env.app_settings["signing_key_ids"] = (
        "RS256 = proxy-RS256\nES256 = proxy-RS256"
    )
    with pytest.raises(ValueError):
        mock_env.make_testapp()


def test_default_signing_alg_inferred(mock_env):
    mock_env.app_settings["signing_key_ids"] = (
        "RS256 = proxy-RS256\nES256 = proxy-ES256"
    )
    mock_env.app_settings.pop("default_signing_alg", None)
    app = mock_env.make_testapp()
    assert app.app.registry.settings["default_signing_alg"] == "RS256"


def test_invalid_default_signing_alg(mock_env):
    mock_env.app_settings["signing_key_ids"] = "RS256 = proxy-RS256"
    mock_env.app_settings["default_signing_alg"] = "ES256"
    with pytest.raises(ValueError):
        mock_env.make_testapp()
