import json
import time

from jwcrypto import jwt
from pyramid.httpexceptions import (
    HTTPBadGateway,
    HTTPBadRequest,
    HTTPForbidden,
    HTTPGatewayTimeout,
    HTTPUnsupportedMediaType,
)
from pyramid.view import view_config

log = __import__("logging").getLogger(__name__)


def includeme(config):
    config.add_route("api.token", "/token")
    config.scan(__name__)


@view_config(
    route_name="api.token",
    request_method="POST",
    renderer="string",
)
def create_token(request):
    registry = request.registry
    settings = registry.settings
    try:
        body = request.json
    except json.JSONDecodeError:
        raise HTTPUnsupportedMediaType from None

    try:
        upstream_token = body["token"]
    except Exception:
        raise HTTPBadRequest from None

    try:
        upstream_jwks = registry.upstream_jwks_cache.value
    except TimeoutError:
        log.warning("timeout while loading upstream jwks cache", exc_info=1)
        raise HTTPGatewayTimeout from None
    except Exception:
        log.warning("error while loading upstream jwks cache", exc_info=1)
        raise HTTPBadGateway from None

    try:
        upstream_token = jwt.JWT(
            jwt=upstream_token,
            key=upstream_jwks,
            check_claims={
                "iss": settings["upstream_issuer"],
                "aud": None,
                "iat": None,
                "nbf": None,
                "exp": None,
            },
        )
    except Exception:
        log.info("failed to decode jwt", exc_info=1)
        raise HTTPForbidden from None
    upstream_claims = json.loads(upstream_token.claims)
    upstream_header = json.loads(upstream_token.header)

    now = int(time.time())
    claims = {
        "iss": settings.get("issuer", request.application_url),
        "aud": upstream_claims["aud"],
        "iat": now,
        "nbf": now,
        "exp": upstream_claims["exp"],
    }
    for key in registry.settings["clone_upstream_claims"]:
        val = upstream_claims.get(key)
        if val is not None:
            claims[key] = val

    supported_signing_keys = registry.signing_keys
    if "alg" in body:
        signing_alg = body["alg"]
        if signing_alg not in supported_signing_keys:
            log.info('client requested unsupported signing alg "%s"', signing_alg)
            raise HTTPForbidden
    else:
        signing_alg = upstream_header.get("alg")
        if signing_alg not in supported_signing_keys:
            signing_alg = settings["default_signing_alg"]
    signing_key = supported_signing_keys[signing_alg]
    new_token = jwt.JWT(
        header={
            "alg": signing_key["alg"],
            "kid": signing_key["kid"],
        },
        claims=claims,
    )
    new_token.make_signed_token(signing_key)
    request.response.content_type = "application/jwt"
    return new_token.serialize()
