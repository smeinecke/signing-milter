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
    libcdb-dev \
    libcmocka-dev \
    libmilter-dev \
    libssl-dev \
    miltertest \
    openssl \
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
    /src/tests/integration/run-miltertest.sh /src/build
