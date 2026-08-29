# syntax=docker/dockerfile:1

# ---- build ----
FROM rust:1.95-alpine AS build

# musl-dev for the C runtime, sqlite is bundled by rusqlite so no libsqlite3
# is needed at build or run time.
RUN apk add --no-cache musl-dev

WORKDIR /src
COPY . .

RUN cargo build --release -p sirna-server --target x86_64-unknown-linux-musl \
 && cp target/x86_64-unknown-linux-musl/release/sirna-server /out-sirna-server

# ---- runtime ----
# Static musl binary, so nothing but the executable is needed. distroless
# nonroot matches the uid the Kubernetes manifest asserts.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out-sirna-server /usr/local/bin/sirna-server

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/sirna-server"]
