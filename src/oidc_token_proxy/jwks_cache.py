import importlib.metadata
import os
import threading
import time
import typing
import urllib.request

import attrs
from jwcrypto import jwk

log = __import__("logging").getLogger(__name__)

package_version = importlib.metadata.version("oidc-token-proxy")


@attrs.define
class Cache:
    max_age: int
    loader: typing.Callable[[], typing.Any]

    lock: threading.RLock = attrs.Factory(threading.RLock)

    _value: typing.Any | None = None
    value_loaded_at: int = 0

    def refresh(self):
        with self.lock:
            self._value = self.loader()
            self.value_loaded_at = time.monotonic()

    @property
    def value(self):
        with self.lock:
            if self.value_loaded_at + self.max_age < time.monotonic():
                self.refresh()
            return self._value


def make_jwks_cache_from_path(
    path: str,
    *,
    max_age: int = 300,
) -> Cache:
    def loader():
        jwks = jwk.JWKSet()
        if os.path.exists(path):
            with open(path) as fp:
                jwks.import_keyset(fp.read())
        else:
            log.warning('could not find jwks file at path "%s"', path)
        return jwks

    return Cache(loader=loader, max_age=max_age)


def make_jwks_cache_from_uri(
    uri: str,
    *,
    headers: dict[str, typing.Any] | None = None,
    max_age: int = 300,
    timeout: int = 30,
) -> Cache:
    if headers is None:
        headers = {}

    headers = {k.lower(): v for k, v in headers.items()}
    headers.setdefault("user-agent", f"oidc-token-proxy/{package_version}")
    headers.setdefault(
        "accept", "application/jwk-set+json, application/json;q=0.9, */*;q=0.8"
    )

    def loader():
        r = urllib.request.Request(url=uri, headers=headers)
        with urllib.request.urlopen(r, timeout=timeout) as response:
            data = response.read().decode("utf8")
        jwks = jwk.JWKSet()
        jwks.import_keyset(data)
        return jwks

    return Cache(loader=loader, max_age=max_age)
