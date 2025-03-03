import json
from jwcrypto import jwk, jwt
import time


def test_jwcrypto():
    """This mostly exists to confirm I'm using jwcrypto correctly."""
    # generate a new JWK
    upstream_key = jwk.JWK.generate(kty="RSA", use="sig", alg="RS256", kid="test-1")

    # create a JWKS with private keys
    upstream_private_jwks = jwk.JWKSet()
    upstream_private_jwks["keys"].add(upstream_key)

    # sign a new JWT from an existing JWKS containing private keys
    upstream_token = jwt.JWT(
        header={"alg": upstream_key.alg, "kid": upstream_key.kid},
        default_claims={
            "iss": "https://me.com",
            "aud": "https://sts.amazonaws.com",
            "iat": None,
            "nbf": None,
            "exp": int(time.time()) + 3600,
        },
        claims={"sub": "foo"},
    )
    upstream_token.make_signed_token(upstream_key)
    upstream_raw_token = upstream_token.serialize()

    # create a JWKS containing only public keys
    raw_upstream_public_jwks = upstream_private_jwks.export(private_keys=False)
    upstream_public_jwks = jwk.JWKSet()
    upstream_public_jwks.import_keyset(raw_upstream_public_jwks)

    # verify JWT against upstream JWKS
    parsed_upstream_token = jwt.JWT(
        jwt=upstream_raw_token,
        key=upstream_public_jwks,
        check_claims={
            "iss": "https://me.com",
            "iat": None,
            "nbf": None,
            "exp": None,
            "aud": None,
            "sub": None,
        },
    )
    claims = json.loads(parsed_upstream_token.claims)
    assert claims["sub"] == "foo"
