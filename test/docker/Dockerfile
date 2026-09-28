# Test environment for tpm2-kira: a software TPM and a virtual smart card.
#
# The base image is a parameter because it decides the pcsc-lite generation, and
# the two generations speak different protocol versions:
#
#   debian:bookworm -> pcsc-lite 1.9.x, protocol 4.4
#   debian:trixie   -> pcsc-lite 2.x,   protocol 4.5
#
# Both are worth running: internal/pcsc implements the wire format by hand, and
# only a live daemon can tell whether it is right.
ARG BASE=debian:trixie
FROM ${BASE}

RUN apt-get update && apt-get install -y --no-install-recommends \
        swtpm swtpm-tools socat tpm2-tools \
        pcscd pcsc-tools vsmartcard-vpcd \
        ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*

# The Go toolchain is bind-mounted from the host rather than installed, so the
# image does not pin a version and needs no network at build time.
ENV PATH=/usr/local/go/bin:$PATH
ENV GOCACHE=/tmp/gocache
ENV GOMODCACHE=/go/pkg/mod

WORKDIR /work
COPY run-tests.sh /usr/local/bin/run-tests
RUN chmod +x /usr/local/bin/run-tests
ENTRYPOINT ["/usr/local/bin/run-tests"]
