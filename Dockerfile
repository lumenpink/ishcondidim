FROM rust:1.85-slim-bookworm AS builder

WORKDIR /app

# Prepara cache de dependências
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs
RUN cargo build --release || true

# Copia código real e compila release final
COPY src ./src
COPY tests ./tests
RUN touch src/main.rs src/lib.rs && cargo build --release

# Imagem de execução mínima
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/ishcondidim /var/lib/ishcondidim/keys /var/lib/ishcondidim/peers

COPY --from=builder /app/target/release/ishcondidim /usr/local/bin/ishcondidim
RUN chmod +x /usr/local/bin/ishcondidim

EXPOSE 8898

CMD ["/usr/local/bin/ishcondidim", "--config", "/etc/ishcondidim/ishcondidim.toml"]
