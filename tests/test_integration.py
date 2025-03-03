from jwcrypto import jwt
import time


def test_api_reissue_token(mock_env):
    mock_env.app_settings["clone_upstream_claims"] = ["sub"]
    testapp = mock_env.make_testapp()

    exp = int(time.time()) + 3600
    upstream_token = mock_env.make_upstream_token(
        kid="upstream-RS256",
        claims={
            "aud": "https://sts.amazonaws.com",
            "sub": "foo",
            "exp": exp,
        },
    )

    response = testapp.post_json(
        "/reissue-token",
        {
            "token": upstream_token,
        },
    )
    assert response.status_code == 200

    jwt.JWT(
        jwt=response.json["token"],
        key=mock_env.reissuer_public_jwks,
        check_claims={
            "iss": "https://reissuer.example.com",
            "aud": "https://sts.amazonaws.com",
            "iat": None,
            "nbf": None,
            "exp": exp,
            "sub": "foo",
        },
    )


def test_api_reissue_token_malformed(mock_env):
    testapp = mock_env.make_testapp()

    testapp.post("/reissue-token", "", status=415)
    testapp.post_json("/reissue-token", {}, status=400)
    testapp.post_json("/reissue-token", {"token": "bad token"}, status=403)


def test_api_reissue_token_unsupported_implicit_alg(mock_env):
    testapp = mock_env.make_testapp()

    exp = int(time.time()) + 3600
    upstream_token = mock_env.make_upstream_token(
        kid="upstream-ES256",
        claims={
            "aud": "https://sts.amazonaws.com",
            "sub": "foo",
            "exp": exp,
        },
    )

    testapp.post_json("/reissue-token", {"token": upstream_token}, status=403)


def test_api_reissue_token_unsupported_explicit_alg(mock_env):
    testapp = mock_env.make_testapp()

    exp = int(time.time()) + 3600
    upstream_token = mock_env.make_upstream_token(
        kid="upstream-RS256",
        claims={
            "aud": "https://sts.amazonaws.com",
            "sub": "foo",
            "exp": exp,
        },
    )

    testapp.post_json(
        "/reissue-token", {"token": upstream_token, "alg": "ES256"}, status=403
    )


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
