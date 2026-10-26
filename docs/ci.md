# CI and releases

GitHub Actions runs `.github/workflows/ci.yml` on pushes, pull requests, and manual requests.

| Check | What it checks |
|---|---|
| Workflow syntax | Pinned version of actionlint |
| Tests | fmt, Clippy, tests, and package builds on Linux/macOS/Windows; Git installation and embedded Skill on Linux |
| Dependency advisories | RustSec through a pinned version of cargo-audit |
| MSRV | Rust 1.90.0 |
| Real Microsandbox isolation | Pinned runtime and image, a real VM, control tests, and failure handling on Linux/KVM |
| VulnBell required checks | Every job above must pass |

CI needs no model credentials and does not run agents against paid services. Contract and policy tests run automatically. Checks that need a live agent account run locally.

The sandbox job needs `/dev/kvm`. It fails if KVM is missing; it does not skip tests or switch backends. GitHub does not guarantee nested virtualization on every runner. Logs and synthetic evidence are saved even when tests fail.

## Releases

A release starts from `.github/workflows/release.sh <version>`. The script verifies `main`, creates a signed tag, publishes to crates.io, and starts the manual release workflow.

The workflow checks the tag and builds Linux x86_64/ARM64, macOS x86_64/ARM64, and Windows x86_64 archives. It publishes them in a GitHub Release with SHA-256 checksums and GitHub build provenance. See [Releasing](releasing.md).
