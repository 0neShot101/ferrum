# Ferrum smoke runtime image: Rust toolchain (pinned by rust-toolchain.toml at build time)
# plus the Debian 13 fixture tools and the isolated Sequoia helper's native build dependencies.
FROM rust:1.99-trixie

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gnupg dpkg-dev curl ca-certificates jq openssl procps util-linux \
        nettle-dev libgmp-dev pkg-config clang libclang-dev \
    && rm -rf /var/lib/apt/lists/* \
    && rustup component add clippy rustfmt

# smoke.sh builds the gateway, origin and isolated verifier into this directory.
ENV PATH="/work/target/release:${PATH}"

WORKDIR /work
CMD ["sleep", "infinity"]
