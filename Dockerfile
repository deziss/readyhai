FROM rust:1-slim-bookworm AS builder
WORKDIR /app
# Dependency layer: dummy main so Cargo.toml/Cargo.lock changes are the only cache buster
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
 && cargo build --release --locked \
 && rm -rf src
COPY src ./src
COPY templates ./templates
COPY tools.lock.toml ./
COPY policies ./policies
RUN touch src/main.rs && cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git openssh-client \
 && rm -rf /var/lib/apt/lists/*
COPY --from=docker:29-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=builder /app/target/release/readyhai /usr/local/bin/readyhai
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin readyhai \
 && mkdir /data && chown readyhai:readyhai /data
ENV READYHAI_DATA=/data
VOLUME /data
USER readyhai
EXPOSE 8080
HEALTHCHECK CMD ["readyhai", "ping"]
ENTRYPOINT ["readyhai"]
CMD ["serve", "--bind", "0.0.0.0:8080"]
