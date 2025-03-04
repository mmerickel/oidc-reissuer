def test_issuer_openid_configuration(mock_env):
    testapp = mock_env.make_testapp()

    response = testapp.get("/.well-known/openid-configuration")
    assert response.status_code == 200
    assert response.content_type == "application/json"
    result = response.json
    assert set(result.keys()) == {
        "issuer",
        "jwks_uri",
        "id_token_signing_alg_values_supported",
        "response_types_supported",
        "subject_types_supported",
        "claims_supported",
    }
    assert result["issuer"] == "https://oidc-proxy.example.com"
    assert result["jwks_uri"] == "https://oidc-proxy.example.com/.well-known/jwks.json"


def test_issuer_openid_configuration_custom_issuer(mock_env):
    mock_env.app_settings["issuer"] = "https://test"
    testapp = mock_env.make_testapp()

    response = testapp.get("/.well-known/openid-configuration")
    assert response.status_code == 200
    assert response.content_type == "application/json"
    result = response.json
    assert set(result.keys()) == {
        "issuer",
        "jwks_uri",
        "id_token_signing_alg_values_supported",
        "response_types_supported",
        "subject_types_supported",
        "claims_supported",
    }
    assert result["issuer"] == "https://test"
    assert result["jwks_uri"] == "https://test/.well-known/jwks.json"


def test_issuer_jwks(mock_env):
    testapp = mock_env.make_testapp()

    response = testapp.get("/.well-known/jwks.json")
    assert response.status_code == 200
    assert response.content_type == "application/jwk-set+json"
    result = response.json
    assert set(result.keys()) == {"keys"}
    assert len(result["keys"]) == 2
    assert {k["kid"] for k in result["keys"]} == {"proxy-RS256", "proxy-ES256"}
