#!/bin/sh
#
# signing-milter - tests/run-all.sh
# Run both unit tests (ctest) and the milter integration tests.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$SCRIPT_DIR/.."
BUILD_DIR="${1:-$SRC_DIR/build}"

# Build the project if the binary is missing.
if [ ! -x "$BUILD_DIR/signing-milter" ]; then
    mkdir -p "$BUILD_DIR"
    cmake -S "$SRC_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release
    cmake --build "$BUILD_DIR" -j"$(nproc 2>/dev/null || echo 2)"
fi

# Run the unit tests.
echo "=== unit tests ==="
ctest --test-dir "$BUILD_DIR" --output-on-failure

# Run the integration tests.
echo "=== integration tests ==="
"$SCRIPT_DIR/integration/run-miltertest.sh" "$BUILD_DIR"
