# Continuous integration and releases

SecureCore uses three GitHub Actions workflows.

## CI

`.github/workflows/ci.yml` runs on pushes to `main` and pull requests. It
performs repository checks and tests GCC/Clang Debug builds plus a GCC Release
build. Every build executes the complete CTest suite.

## Security testing

`.github/workflows/security.yml` runs ASan/UBSan, focused TSan tests, and all
six libFuzzer smoke targets. It runs on pull requests, pushes to `main`, a
weekly schedule, and manual dispatch.

Local equivalents:

```bash
scripts/run-sanitizers.sh
SECURECORE_FUZZ_SECONDS=10 scripts/run-fuzz-smoke.sh
```

Sanitizers can be selected independently:

```bash
SECURECORE_SANITIZER_MODE=asan-ubsan scripts/run-sanitizers.sh
SECURECORE_SANITIZER_MODE=tsan \
SECURECORE_REQUIRE_TSAN=1 \
scripts/run-sanitizers.sh
```

## Tagged releases

Pushing a semantic-version tag such as `v1.0.1` starts
`.github/workflows/release.yml`. The workflow:

1. builds the Release binaries twice from clean build directories;
2. creates deterministic `tar.gz` archives;
3. compares both SHA-256 digests;
4. generates a GitHub artifact attestation;
5. publishes the archive and checksum to a GitHub Release.

Create a release after `main` is clean and fully tested:

```bash
git tag -a v1.0.1 -m "SecureCore v1.0.1"
git push origin v1.0.1
```

The package contains:

```text
bin/secure-server
bin/secure-admin
configs/
docs/
BUILD_INFO.json
DEPENDENCIES.txt
```

Verify the checksum:

```bash
sha256sum -c SecureCore-1.0.0-linux-x86_64.tar.gz.sha256
```

For a public repository, verify GitHub build provenance with GitHub CLI:

```bash
gh attestation verify \
    SecureCore-1.0.0-linux-x86_64.tar.gz \
    --repo Bandiaozia/SecureCore
```

## Action dependency updates

`.github/dependabot.yml` checks GitHub Actions dependencies every week. Review
major-version updates before merging them because a new action runtime may
require a newer self-hosted runner.
