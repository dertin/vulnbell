# Microsandbox

Microsandbox **0.7.11** is the only backend for active tests. Tests never fall back to host processes. Real execution has been tested on Linux x86_64/KVM. Upstream also supports macOS Apple Silicon and Windows/WHP; VulnBell still needs real VM tests on those systems. Upstream support is not proof that this integration works there.

## Setup

Install the runtime from its official [v0.7.11 release](https://github.com/superradcompany/microsandbox/releases/tag/v0.7.11). On Linux the user needs read/write access to `/dev/kvm`. Then run:

```sh
msb --version
msb doctor
vulnbell sandbox prepare
vulnbell sandbox status
```

`prepare` checks the version and prerequisites. It uses a private VulnBell `MSB_HOME` and downloads and prepares an official OCI image pinned by digest. The base image is Alpine 3.22.7, index `sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f`. It also records the architecture-specific manifest digest and executable SHA-256. The global Microsandbox installation is not changed. Set `VULNBELL_MSB_EXECUTABLE` to select the executable during setup. If `msb` is missing or has another version, `prepare` and `doctor` name the release to install. When `msb doctor` fails, they show its failing checks.

Report JSON lists `verification_pending` for open cases that lack an impact assessment, or that have a `needs_evidence` verdict and no recorded local test or blocker. The Markdown report starts with an incomplete-report banner until those items are resolved. `case <id> --validation-blocker <reason>` records the blocker for every instance of the case; add `--instance <id>` to limit it to one.

A current `lab_reproduced` attestation confirms the affected version only for the instance it tested. In a case with several instances, for example every artifact of one upstream release, `impact` can then derive an update priority from that instance while the others stay unconfirmed.

For a local project, stage only the reviewed files needed by the test:

```sh
vulnbell sandbox stage --source /path/to/project --file package-lock.json --file src/affected.ts --directory /private/test
```

Static source review happens before sandboxing and does not execute project code. Use `stage` only when a dynamic check is necessary. The command creates a deterministic archive and manifest from an explicit reviewed file list. It rejects symlinks, traversal, common secret files, oversized input, and an existing destination. It never runs project hooks or build tools. Record `context.mode: workspace_copy` for this path.

Without a workspace, assess the advisory, affected source, fix, and exact artifact in general terms. If execution would resolve a material uncertainty, build a minimal project from checksummed official artifacts and record `context.mode: artifact_reproducer`. This can validate behavior under the tested conditions, but it cannot establish how an unavailable project uses the component.

If a test needs Node, PHP, Rust, or other tools, prepare an official image with `sandbox prepare --image <reference>`. Use `docker.io/library/...@sha256:<64 hex>`; mutable tags are rejected. The image and tools must fit the private 2 GiB disk and memory/time limits. Not every build will fit. Preparing an image does not prove it matches the installed binary. Tool downloads are a separate HTTPS step; the test itself has no network access.

## Execution and limits

- Approve the script, test oracle, and inputs with `verify --authorize`. This flag represents the local operator's authority. It does not identify a person or provide cryptographic approval. The scheduled researcher cannot call it.
- Inputs must be in `inputs/` beside the test file. That folder cannot redirect elsewhere. Names must be unique and hashes must match. Limits: 20 files, 16 MiB per file, 64 MiB total. Validated bytes are copied; the folder is not mounted.
- Tests use UID/GID 65534, the `restricted` profile, `multi-tenant` deployment, 1 CPU, 128–512 MiB RAM, and 1–120 seconds. Each VM has a private 2 GiB disk, a maximum lifetime, and forced removal after the test.
- Traffic is denied in both directions. There are no network exceptions, published ports, secrets, host certificates, or external mounts. `--no-net` keeps a network device with a deny policy; it does not remove the device. The runtime checks that policy before running the test.
- Test specifications accept only the script and inputs. They cannot add runtime flags, mounts, secrets, or network settings. The **active** policy returned by the runtime is checked before execution.
- Tests use managed Microsandbox jobs. Job identity and final status come from control JSON. Workload logs are fetched separately. Stdout/stderr cannot set the trusted exit code or timeout. Log capture and host processes have their own limits.
- A setup, policy, execution, capture, or cleanup failure cannot produce a successful verification. A missing runtime means inconclusive. A failed reproduction cannot justify dismissal.

Version 2 attestations record the project, case, facts, instance, version, runtime, image, policy, job, input/output hashes, resources, and observations. Attestations must use the current schema. Hashes are local integrity records. They do not certify the hypervisor remotely or prove that a test oracle is correct.

## Tests and CI

Run `cargo test --test sandbox_live --locked -- --ignored --nocapture` for real VM tests. The suite checks:

- A host file stays unreadable and unchanged; the guest runs as a non-root user.
- Public, private, metadata, and DNS connections are denied; privileged writes fail.
- Fake status markers and exit code 10 cannot pass when code 1 is expected.
- Inputs outside the allowed folder, bad hashes, and path traversal are rejected.
- Synthetic reproduction, positive controls, limited non-applicability evidence, outdated attestations, and inconclusive timeouts work as expected.

Synthetic cases and evidence are saved. Linux CI requires `/dev/kvm`, installs the official 0.7.11 archive with a pinned SHA-256, and runs this suite. Missing virtualization fails the job without skipping tests or changing backends. Evidence is saved even on failure. This check blocks the release workflow. Core builds on macOS/Windows do not replace real VM tests on those systems.

Sources: [project and requirements](https://github.com/superradcompany/microsandbox), [networking and SDK/CLI differences](https://docs.microsandbox.dev/networking/overview), [protocol and compatibility](https://github.com/superradcompany/microsandbox/blob/main/COMPATIBILITY.md), [pinned release](https://github.com/superradcompany/microsandbox/releases/tag/v0.7.11).
