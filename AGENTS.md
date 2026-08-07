# Agent notes for signing-milter

## Project layout

- `src/` — C source and headers. `src/utils/` and `src/ctxdata/` are submodules.
- `docs/` — `signing-milter.8` man page.
- `scripts/` — `add-repository.sh` helper script.
- `tests/unit/` — cmocka unit tests.
- `tests/integration/` — miltertest Lua integration tests.
- `debian/`, `signing-milter.spec`, `run_signing-milter` — packaging; kept at the repo root.

## Build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

The `signing-milter` binary is placed at `build/signing-milter`.

## Test

```bash
ctest --test-dir build --output-on-failure
./tests/run-all.sh build
```

`run-all.sh` runs ctest and then the milter integration suite. The baseline
integration suite needs `miltertest` installed. The auth-signing tests use
`python3-miltertest`; the Redis variant also needs a local `redis-server`.

## Debian package

```bash
dpkg-buildpackage -us -uc -b
```

If `shellcheck` is not installed, use `-d` to override the build dependency.
