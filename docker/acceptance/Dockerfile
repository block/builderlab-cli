FROM rust:1.91.1-bookworm AS build

WORKDIR /src
COPY . .
WORKDIR /src
RUN cargo build --locked --release --bin bl

FROM python:3.12-slim-bookworm

RUN groupadd --gid 10001 acceptance && useradd --uid 10001 --gid acceptance --create-home --shell /usr/sbin/nologin acceptance
COPY --from=build /src/target/release/bl /usr/local/bin/bl
COPY --chown=acceptance:acceptance --chmod=755 docker/acceptance /opt/bl-acceptance

USER acceptance
ENTRYPOINT ["/opt/bl-acceptance/run-acceptance.sh"]
