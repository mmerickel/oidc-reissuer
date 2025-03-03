from jwcrypto import jwt
import time

from webtest.http import StopableWSGIServer


def test_reissue_token_works(mock_env):
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


def test_reissue_token_malformed(mock_env):
    testapp = mock_env.make_testapp()

    testapp.post("/reissue-token", "", status=415)
    testapp.post_json("/reissue-token", {}, status=400)
    testapp.post_json("/reissue-token", {"token": "bad token"}, status=403)


def test_reissue_token_unsupported_implicit_alg(mock_env):
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


def test_reissue_token_unsupported_explicit_alg(mock_env):
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


def test_reissue_token_from_upstream_jwks_uri(mock_env):
    def app(environ, start_response):
        start_response(
            "200 OK",
            [
                ("Content-Type", "application/json"),
            ],
        )
        yield mock_env.upstream_public_jwks.export(private_keys=False).encode("utf8")

    server = StopableWSGIServer.create(app)
    server.wait()

    del mock_env.app_settings["upstream_jwks_file"]
    mock_env.app_settings["upstream_jwks_uri"] = server.application_url + "jwks"

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

    testapp.post_json("/reissue-token", {"token": upstream_token})
    server.shutdown()


def test_reissue_token_from_upstream_jwks_uri_bad_gateway(mock_env):
    def app(environ, start_response):
        start_response("404 Not Found", [])
        yield b""

    server = StopableWSGIServer.create(app)
    server.wait()

    del mock_env.app_settings["upstream_jwks_file"]
    mock_env.app_settings["upstream_jwks_uri"] = server.application_url + "jwks"

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

    testapp.post_json("/reissue-token", {"token": upstream_token}, status=502)
    server.shutdown()


def test_reissue_token_from_upstream_jwks_uri_timeout(mock_env):
    def app(environ, start_response):
        time.sleep(2)
        start_response(
            "200 OK",
            [
                ("Content-Type", "application/json"),
            ],
        )
        yield mock_env.upstream_public_jwks.export(private_keys=False).encode("utf8")

    server = StopableWSGIServer.create(app)
    server.wait()

    del mock_env.app_settings["upstream_jwks_file"]
    mock_env.app_settings["upstream_jwks_uri"] = server.application_url + "jwks"
    mock_env.app_settings["upstream_timeout"] = 1

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

    testapp.post_json("/reissue-token", {"token": upstream_token}, status=504)
    server.shutdown()
