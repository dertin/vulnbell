# Releasing

VulnBell publishes its crate to crates.io and prebuilt archives through GitHub Actions.

## Release

1. Update `Cargo.toml` and `CHANGELOG.md`.
2. Confirm `main` is clean, synchronized with `origin/main`, and has a successful CI run.
3. Run:

```sh
./.github/workflows/release.sh 0.1.0
```

The script verifies the version, runs `cargo publish --dry-run`, creates and pushes a signed tag, publishes the crate, starts the GitHub release workflow, and waits for it to finish.

The workflow checks the tag and builds:

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
- `x86_64-pc-windows-msvc`

Each archive includes the binary, Agent Skill, schemas, examples, and user documentation. GitHub publishes SHA-256 checksums and build provenance attestations.

Verify an archive with:

```sh
gh attestation verify vulnbell-x86_64-unknown-linux-gnu-v0.1.0.tgz \
  -R dertin/vulnbell
```

If crates.io publication fails after the tag is pushed, inspect crates.io before retrying. Running the script again with an existing tag only resumes the GitHub release workflow; it does not republish the crate.
