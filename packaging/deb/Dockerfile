# The Debian build environment of packaging/build-packages.sh: Debian 13
# with the Go release the build asks go.dev for (GOVER), the way the
# release workflow installs it.
#
#   docker build -t tpm2-kira-deb-build:go1.27.2 --build-arg GOVER=go1.27.2 packaging/deb
FROM debian:13
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential debhelper dpkg-dev ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
ARG GOVER
RUN test -n "$GOVER" && curl -fsSL "https://go.dev/dl/${GOVER}.linux-amd64.tar.gz" | tar -C /usr/local -xz
ENV PATH=/usr/local/go/bin:$PATH
