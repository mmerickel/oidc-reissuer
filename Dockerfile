FROM public.ecr.aws/docker/library/python:3.13-slim-bookworm AS base

FROM base AS builder

# install uv
COPY --from=ghcr.io/astral-sh/uv:0.6.4 /uv /uvx /bin/

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BITCODE=1

WORKDIR /app

# sync remote dependencies
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock,z \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml,z \
    uv sync --frozen --no-install-project --no-editable --all-extras

ADD . /app

# build the app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-editable --extra app

FROM base

ENV PATH="/app/.venv/bin:$PATH"

# app user
RUN useradd app --home-dir /app

# copy the environment, but not the source code
COPY --from=builder --chown=app /app/.venv /app/.venv

WORKDIR /app
USER app

# run the application
CMD ["pserve", "site.ini"]
