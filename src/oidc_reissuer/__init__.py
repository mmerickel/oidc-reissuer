from jwcrypto import jwk
from pyramid.config import Configurator
from pyramid.settings import aslist

from .jwks_cache import make_jwks_cache_from_path, make_jwks_cache_from_uri


def parse_map(value):
    result = value
    if isinstance(value, str):
        result = {}
        for line in aslist(value, flatten=False):
            if line:
                alg, kid = line.split("=", 1)
                result[alg.strip()] = kid.strip()
    return result


def main(global_config, **settings):
    settings["upstream_timeout"] = int(settings.get("upstream_timeout") or 30)
    settings["upstream_jwks_cache_max_age"] = int(
        settings.get("upstream_jwks_cache_max_age") or 300
    )
    if settings.get("upstream_jwks_file"):
        upstream_jwks_cache = make_jwks_cache_from_path(
            settings["upstream_jwks_file"],
            max_age=settings["upstream_jwks_cache_max_age"],
        )
    else:
        upstream_jwks_cache = make_jwks_cache_from_uri(
            settings["upstream_jwks_uri"],
            max_age=settings["upstream_jwks_cache_max_age"],
            timeout=settings["upstream_timeout"],
        )
    print(upstream_jwks_cache.value)

    issuer_jwks = jwk.JWKSet()
    with open(settings["jwks_file"]) as fp:
        issuer_jwks.import_keyset(fp.read())

    settings["signing_key_ids"] = parse_map(settings["signing_key_ids"])
    settings["clone_upstream_claims"] = aslist(settings["clone_upstream_claims"])
    signing_keys = {}
    for alg, kid in settings["signing_key_ids"].items():
        try:
            signing_keys[alg] = next(
                k
                for k in issuer_jwks.get_keys(kid)
                if k.has_private and k["use"] == "sig" and k["alg"] == alg
            )
        except StopIteration:
            raise ValueError(
                f'could not find a signing key for alg "{alg}" kid "{kid}"'
            )

    with Configurator(settings=settings) as config:
        registry = config.registry
        registry.upstream_jwks_cache = upstream_jwks_cache
        registry.issuer_jwks = issuer_jwks
        registry.signing_keys = signing_keys

        config.include(".api")
        config.include(".issuer")

        return config.make_wsgi_app()
