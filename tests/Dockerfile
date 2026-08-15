# signing-milter - tests/Dockerfile
# Build and test signing-milter on a configurable Debian/Ubuntu version.

ARG OS_VERSION=debian:trixie
FROM ${OS_VERSION}

ENV DEBIAN_FRONTEND=noninteractive

# Buster is archived; move to archive.debian.org before apt-get update.
RUN . /etc/os-release && \
    if [ "$ID" = "debian" ] && [ "$VERSION_ID" = "10" ]; then \
        find /etc/apt -name '*.list' -exec \
            sed -i 's|deb.debian.org|archive.debian.org|g; s|security.debian.org|archive.debian.org|g; /-updates/d' {} +; \
    fi

ARG WITH_REDIS=ON

# Install build and test dependencies.  Redis packages are only needed when
# WITH_REDIS is enabled; on older distros the packaged hiredis is too old.
# python3-miltertest is optional and only available on newer releases.
RUN apt-get update && \
    REDIS_PKGS="" && \
    if [ "$WITH_REDIS" = "ON" ]; then REDIS_PKGS="libhiredis-dev redis-server redis-tools"; fi && \
    PYMILTER_PKG="" && \
    if apt-cache show python3-miltertest >/dev/null 2>&1; then PYMILTER_PKG="python3-miltertest"; fi && \
    MILTER_PKG="" && \
    if apt-cache show miltertest >/dev/null 2>&1; then MILTER_PKG="miltertest"; fi && \
    apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    pkg-config \
    iproute2 \
    libcdb-dev \
    libcmocka-dev \
    libmilter-dev \
    libssl-dev \
    openssl \
    postfix \
    swaks \
    tinycdb \
    $REDIS_PKGS \
    $PYMILTER_PKG \
    $MILTER_PKG \
    && rm -rf /var/lib/apt/lists/*

# Create an unprivileged test user.  signing-milter refuses to run as root,
# and the unit/integration tests need to be able to write to /src/build.
RUN useradd -m -s /bin/sh test

# Copy the source tree.
WORKDIR /src
COPY . /src
RUN chown -R test:test /src

# Build and test as the unprivileged user.
USER test
RUN rm -rf /src/build && \
    cmake -S /src -B /src/build -DCMAKE_BUILD_TYPE=Release -DWITH_REDIS=${WITH_REDIS} && \
    cmake --build /src/build -j $(nproc) && \
    /src/tests/run-all.sh /src/build

# Run the real Postfix end-to-end test as root.
USER root
RUN /src/tests/integration/run-postfix.sh /src/build

USER test
