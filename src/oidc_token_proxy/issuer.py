from pyramid.view import view_config


def includeme(config):
    config.add_route("issuer.openid-configuration", "/.well-known/openid-configuration")
    config.add_route("issuer.jwks", "/.well-known/jwks.json")
    config.scan(__name__)


@view_config(
    route_name="issuer.openid-configuration",
    request_method="GET",
    renderer="json",
)
def openid_configuration(request):
    supported_claims = {"iss", "aud", "iat", "nbf", "exp"}
    supported_claims.update(request.registry.settings["clone_upstream_claims"])
    supported_alg_values = request.registry.settings["signing_key_ids"].keys()
    return {
        "issuer": request.application_url,
        "jwks_uri": request.route_url("issuer.jwks"),
        "response_types_supported": ["id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": sorted(supported_alg_values),
        "claims_supported": sorted(supported_claims),
    }


@view_config(
    route_name="issuer.jwks",
    request_method="GET",
    renderer="json",
)
def jwks_uri(request):
    request.response.content_type = "application/jwk-set+json"
    return request.registry.issuer_jwks.export(private_keys=False, as_dict=True)
