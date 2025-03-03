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
    assert result["issuer"] == "https://reissuer.example.com"
    assert result["jwks_uri"] == "https://reissuer.example.com/.well-known/jwks.json"


def test_issuer_jwks(mock_env):
    testapp = mock_env.make_testapp()

    response = testapp.get("/.well-known/jwks.json")
    assert response.status_code == 200
    assert response.content_type == "application/jwk-set+json"
    result = response.json
    assert set(result.keys()) == {"keys"}
    assert len(result["keys"]) == 1
    assert result["keys"][0]["kid"] == "reissuer-RS256"
