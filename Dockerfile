ARG BASE_IMAGE=public.ecr.aws/docker/library/python:3.13-slim-bookworm

FROM ${BASE_IMAGE} AS base

FROM base AS builder

ARG UV_VERSION=0.6.4

COPY --from=ghcr.io/astral-sh/uv:${UV_VERSION} /uv /uvx /bin/

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BITCODE=1

WORKDIR /app

RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock,z \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml,z \
    uv sync --frozen --no-install-project --no-editable --all-extras

ADD . /app

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-editable --extra app

FROM base

RUN useradd app --home-dir /app

COPY --from=builder --chown=app /app/.venv /app/.venv

WORKDIR /app
USER app

ENV PATH="/app/.venv/bin:$PATH"

CMD ["pserve", "site.ini"]
