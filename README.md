# oidc-token-proxy

`oidc-token-proxy` can turn a private OIDC `id_token` into a public one.

## Usage

### Create a python virtualenv

See the `example` folder for a working `site.ini` and example JWKS files.

```shell
$ uv init --bare
$ uv add 'oidc-token-proxy[app]'
$ uv run pserve site.ini
```

### Embed in your own WSGI app/server

The `oidc-token-proxy` is a basic WSGI application and can be run however you wish.

```python
from oidc_token_proxy import main

settings = {
    "upstream_issuer": "https://gitlab.com",
    "upstream_jwks_uri": "https://gitlab.com/oauth/discovery/keys",
    # ... other settings
}
wsgiapp = main({}, **settings)
```

## Configuration

### jwks_file

**Required**

This must be the path to a standard JWKS file containing private keys.
For example, you can generate keys at https://jwkset.com/generate.

```json
{
    "keys": [
        {
          "kty": "RSA",
          "use": "sig",
          "alg": "RS256",
          "kid": "23c017d1-dc52-4ec2-99f7-8cd109efdc81",
          "d": "xv7sblmG7nPtJ51skiuj0Yu87hEiJgWFEb7vT85EhJY3xqub6OFuCm3w3ZLhehg1Rjlo8nbrMg1TdZ1W3T97IalxjtRoY2vhkF3FmvLSaNVEFlXqNyCnc9l3h7TuznRpcgrRp6CDDLb5Wv6R-i2Fm-Rn9JqCFuorexEND9ddZ88qEiSK2uDuAabftuqkd6WibU8Mi-d4lVqbNkZXcRluTZdNNT0HDW0rwG09ZDagL119htyPKAzWSB-h3whyfJsnp-xyIqwIXTc0JpdHF3OfKzzXXbhAYba-SlOoBem0fV-2tn8cTLF4TwYIuRPNyshlPd1TOfaM_-Qq53CaQsKKEQ",
          "n": "4hk3H6qYzqfJ-eVGIpegcR5z3yqctY55wSDg4xVPKwOOfhGhkOrvmaeq8bHNs6TNDkfeW5zgK0iewjpq8g-mmhaNLjJ1en29GYDfOiEI_qUYq5JzKILnJxmnjUP__03eKkeNJnClBJEn-89ckigcjYRA2wJ3XgrQLxCoOsgNmFMXAbT_NdPRUkYWhpkO-_MO9ToGEROe8-GBOwFpUtH4L-uZ9HbqEU0-yEncnzwhl6veaROHLBTQLC-CzQm5uO1IhOr8E3Q4N0JBAP0tRt7u2gBRZ5pQrooax82gZ_JJzJs__K5lpF00HaCsIHcfK4PJVOQ9CYfkJ1qqGn7AIK0I_w",
          "e": "AQAB",
          "p": "9q2XEyb4JHRJj7UcP_IwUFdo4rwb8acy0RIYA-2sQLhuVrrEgVEPdxR8OxKZ2uJzxO1RvEQkHYQU_fySfUXcoEPLfZvE_rRvNiQwXe1iUUH_i71wEGwM9pncy5Bg0FjQmksSMZy70PBhRXSN4o0ZceW2X2W4woqbFMK_H0Kcq5k",
          "q": "6qSIzq8j7N9QYWMu68dVbCViWiupOsN7vU5pfQJColvKz-1mEh_Dh2vUNZMhn84LH47JooQCedEXPS7mg0z7gOw02JABTNjg7Y2zUqDc_Qm21Dgyt_nZJAzpcLRtgocwqLFt0gtFUR604sfsNN8dXF0uAwfMYlv5-26bhBxXeFc",
          "dp": "oTa76GFshO6W8NuNdeFDYA5wVtZXcOwz0t1_YnnfPIEMY5Q2PsmKUOnLcxPqB1o-DPKIm4DxFXUv_volhse0s-z6vcGi0k976ydlkM1GlxKJ_3q0FZd4NWZDHarjCucwldYAMvpa6OdguvK8k9ZhTcWyFdC2GjZZugy4uaZgG-k",
          "dq": "uMpdh9C8zUbNyfTPthZlOudyPqtV-paLc_o176KBEdaSshA3q5xiY9tS4-J8v5sIfZD5UUj_nipCUAgIuG0_QThFIiy_KWNAOTW4fSF9CLbGyvl7UBKvpMmaaw1dlUec1a3uXFZN_-Xb9SIX70ermtszamWQ3AGtrQtd5LxhUr8",
          "qi": "xD4_r74SUBeUFAtkrVFWppYWjTqj0YmKh3xABwV_qf4g9F29999aZ7X_gbEBgQ2Ltyw8GxjvGqYIIzHyH6v3YTZoCPMWnY50rQYSZPIi9zSfF1BgZpkcvKzPbFpD8OA1g7chL0Dc14IGqhPLRW8OJKMJhVJ_qs0aMSD0pawd1Jw"
        },
        {
          "kty": "EC",
          "use": "sig",
          "alg": "ES256",
          "kid": "7695e425-1109-4ee2-ac1f-dc3d6ed9fe94",
          "crv": "P-256",
          "x": "6HdpKTiaGxishAbzrIHbhXSLOPvM0vu0LsccB_X-5bU",
          "y": "nEZQq61TC3raKz3pNHKyxPG0mzeUex1XOhcGn2IBhkA",
          "d": "Jt5cDGh4HBzebukQbzcP4rmvM6ZyXN-mhfLv3HhOT0s"
        },
        {
          "kty": "EC",
          "use": "sig",
          "alg": "ES256",
          "kid": "7695e425-1109-4ee2-ac1f-dc3d6ed9fe94",
          "crv": "P-256",
          "x": "zk7wRhnD3L_CGb2XfLba0xLgkuyMlX8GjuCc5kKAV8g",
          "y": "PGckLY79Sye1143kmIqrRwcnbPnXJYj9dfELz8-skVY",
          "d": "a9jmgYldx1guUbWwjZhL0DYzPTf3vY2JUyrnDC_uETA"
        }
    ]
}
```

### signing_key_ids

**Required**

A mapping of `algorithm = kid` defining a specific JWK within the above `jwks_file` that should be used for signing keys for a specific algorithm.

This is necessary any time there are multiple keys for a specific algorithm because they have been rotated over time.

```ini
RS256 = 23c017d1-dc52-4ec2-99f7-8cd109efdc81
ES256 = 7695e425-1109-4ee2-ac1f-dc3d6ed9fe94
```

### default_signing_alg

**Optional**

The default algorithm used to sign new keys when all other options fail to determine an appropriate signing key.
This algorithm must match to a selected key via the `signing_key_ids` map.

If a value is not supplied then the first algorithm in ``signing_key_ids`` will be used automatically when other algorithm negotiation fails.

### issuer

**Optional**

The issuer url for the proxy.
The `{issuer}/.well-known` endpoints need to be hosted at this base.
For example, `https://oidc-proxy.example.com`.

By default, this is `request.application_url` which is dynamic relative to the current request.
However, if you're hosting the proxy in a way that it is accessible by multiple URL endpoints (like a private host vs a public host) you need to set this statically so that the generated tokens will be creatable and verifiable consistently.

### upstream_issuer

**Required**

The issuer will be validated on upstream tokens.

For example, `https://gitlab.com`.

### upstream_jwks_uri

**Optional**

The URI where the JWKS can be loaded from to verify upstream tokens.

### upstream_jwks_cache_max_age

**Optional**

The number of seconds to store the upstream JWKS in memory before requesting an updated copy for future requests.
This must be greater than 0.

Default: `300`.

### upstream_timeout

**Optional**

The number of seconds to wait before failing to access the upstream endpoints.

Default: `30`.

### upstream_jwks_file

**Optional**

If the upstream JWKS URI is not accessible then it is possible to self-host the JWKS file within the `oidc-token-proxy`.
If set, this setting will be used instead of loading the JWKS from the `upstream_jwks_uri` setting.

### clone_upstream_claims

**Optional**

If you do not specify this parameter then the created token will only have the following claims:
- `iss` - defined by the hosted URL of the `oidc-token-proxy`.
- `aud` - copied from the upstream claims
- `iat` - system time when token is created
- `nbf` - system time when token is created
- `exp` - copied from the upstream claims

To clone any other values, specify them here or they will be stripped from the final token.

```
sub
ref
ref_protected
```

### extra_request_headers

**Optional**

HTTP headers to add to requests when accessing remote systems.
For example a custom user-agent.

```
user-agent = my-oidc-token-proxy
x-custom = foo
```

## API endpoints

### GET /.well-known/openid-configuration

### GET /.well-known/jwks.json

### POST /token

#### Request Parameters

##### token

**Required**

The upstream JWT to be verified and converted to a new token.

##### alg

**Optional**

Explicit request for a key signed via the desired algorithm.
Can be used to guarantee you get back a key with the desired algorithm.

#### Response

##### application/jwt

The newly-minted JWT signed by `oidc-token-proxy`.

## Enable AWS IAM AssumeRoleWithWebIdentity for private Gitlab instances

**Official reference**: https://docs.gitlab.com/ci/secrets/id_token_authentication/

You have a private Gitlab instance and you want your CI/CD jobs to authenticate via OIDC with AWS IAM to perform operations in your AWS account.

AWS IAM requires an OIDC provider to be publically accessible to verify the tokens minted by the Gitlab server.

This is where the `oidc-token-proxy` comes into play as a middle-man that can safely expose the identity without exposing the entirety of your private OIDC provider.

### Setup oidc-token-proxy

Setup `oidc-token-proxy` following the documentation.
Let's assume it will be hosted at `https://oidc-proxy.example.com` and your Gitlab server is hosted at `https://gitlab.internal`.

```ini
upstream_issuer = https://gitlab.internal
clone_upstream_claims =
  sub
```

### Configure a CI/CD job

```yaml
job_with_id_tokens:
  id_tokens:
    PRIVATE_ID_TOKEN_FOR_AWS:
      aud: https://sts.amazonaws.com
  script:
    # this first step uses the oidc-token-proxy to translate PRIVATE_ID_TOKEN_FOR_AWS
    # into PUBLIC_ID_TOKEN_FOR_AWS
    - >
      PUBLIC_ID_TOKEN_FOR_AWS=$(curl
      https://oidc-proxy.example.com/token
      -X POST
      -H 'Content-Type: application/json'
      -H 'Accept: application/jwt'
      --data "{\"token\": $PRIVATE_ID_TOKEN_FOR_AWS}")
    - >
      aws_sts_output=$(aws sts assume-role-with-web-identity
      --role-arn ${ROLE_ARN}
      --role-session-name "GitLabRunner-${CI_PROJECT_ID}-${CI_PIPELINE_ID}"
      --web-identity-token "$PUBLIC_ID_TOKEN_FOR_AWS"
      --duration-seconds 3600
      --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]'
      --output text)
    - export $(printf "AWS_ACCESS_KEY_ID=%s AWS_SECRET_ACCESS_KEY=%s AWS_SESSION_TOKEN=%s" $aws_sts_output)
    - aws sts get-caller-identity
```
