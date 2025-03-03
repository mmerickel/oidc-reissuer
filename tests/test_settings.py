import pytest


def test_invalid_signing_key_config(mock_env):
    mock_env.app_settings["signing_key_ids"] = {"ES256": "doesnt exist"}
    with pytest.raises(ValueError):
        mock_env.make_testapp()
