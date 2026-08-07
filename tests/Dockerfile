# signing-milter - tests/Dockerfile
# Build and test signing-milter on Debian trixie.

FROM debian:trixie

ENV DEBIAN_FRONTEND=noninteractive

# Install build and test dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    pkg-config \
    iproute2 \
    libcdb-dev \
    libcmocka-dev \
    libhiredis-dev \
    libmilter-dev \
    libssl-dev \
    miltertest \
    python3-miltertest \
    openssl \
    postfix \
    redis-server \
    redis-tools \
    swaks \
    tinycdb \
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
    cmake -S /src -B /src/build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build /src/build -j$(nproc) && \
    ctest --test-dir /src/build --output-on-failure && \
    /src/tests/integration/run-miltertest.sh /src/build && \
    /src/tests/integration/run-miltertest-auth.sh /src/build && \
    /src/tests/integration/run-miltertest-auth-redis.sh /src/build

# Run the real Postfix end-to-end test as root.
USER root
RUN /src/tests/integration/run-postfix.sh /src/build

USER test
