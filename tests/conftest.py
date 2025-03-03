import attrs
from jwcrypto import jwk, jwt
import pytest
import typing
from webtest import TestApp


from oidc_token_proxy import main

upstream_RS256 = jwk.JWK.generate(
    kty="RSA", use="sig", alg="RS256", kid="upstream-RS256"
)
upstream_ES256 = jwk.JWK.generate(
    kty="EC", use="sig", alg="ES256", kid="upstream-ES256"
)
proxy_RS256 = jwk.JWK.generate(kty="RSA", use="sig", alg="RS256", kid="proxy-RS256")
proxy_ES256 = jwk.JWK.generate(kty="EC", use="sig", alg="ES256", kid="proxy-ES256")


@attrs.define
class MockEnv:
    upstream_private_jwks: jwk.JWKSet
    upstream_public_jwks: jwk.JWKSet

    proxy_private_jwks: jwk.JWKSet
    proxy_public_jwks: jwk.JWKSet

    app_settings: dict[str, typing.Any]

    def make_upstream_token(
        self,
        *,
        kid: str,
        claims: dict[str : typing.Any] | None = None,
        now: int | None = None,
    ) -> str:
        key = self.upstream_private_jwks.get_key(kid)
        upstream_token = jwt.JWT(
            header={"alg": key["alg"], "kid": kid},
            default_claims={
                "iss": self.app_settings["upstream_issuer"],
                "iat": None,
                "nbf": None,
            },
            claims=claims,
        )
        upstream_token.make_signed_token(key)
        return upstream_token.serialize()

    def make_testapp(self) -> TestApp:
        app = main({}, **self.app_settings)
        return TestApp(
            app,
            extra_environ={
                "HTTP_HOST": "oidc-proxy.example.com",
                "wsgi.url_scheme": "https",
            },
        )


@pytest.fixture
def mock_env(tmp_path):
    upstream_private_jwks = jwk.JWKSet()
    upstream_private_jwks["keys"].add(upstream_RS256)
    upstream_private_jwks["keys"].add(upstream_ES256)
    with open(tmp_path / "upstream_jwks.json", "w") as fp:
        fp.write(upstream_private_jwks.export(private_keys=False))

    upstream_public_jwks = jwk.JWKSet()
    upstream_public_jwks.import_keyset(upstream_private_jwks.export(private_keys=False))

    proxy_private_jwks = jwk.JWKSet()
    proxy_private_jwks["keys"].add(proxy_RS256)
    proxy_private_jwks["keys"].add(proxy_ES256)
    with open(tmp_path / "jwks.json", "w") as fp:
        fp.write(proxy_private_jwks.export())

    proxy_public_jwks = jwk.JWKSet()
    proxy_public_jwks.import_keyset(proxy_private_jwks.export(private_keys=False))

    app_settings = {
        "upstream_issuer": "https://oidc.example.com",
        "upstream_jwks_file": tmp_path / "upstream_jwks.json",
        "jwks_file": tmp_path / "jwks.json",
        "signing_key_ids": "RS256 = proxy-RS256\n\n",
        "clone_upstream_claims": [
            "sub",
        ],
    }

    return MockEnv(
        upstream_private_jwks=upstream_private_jwks,
        upstream_public_jwks=upstream_public_jwks,
        proxy_private_jwks=proxy_private_jwks,
        proxy_public_jwks=proxy_public_jwks,
        app_settings=app_settings,
    )
