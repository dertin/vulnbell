# Contribute

You need Rust 1.90+ and a C compiler. Use concrete types, explicit states, bounded processes, and errors that explain what failed.

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo package --locked --allow-dirty
```

Rust types define the data contracts. Generate schemas with `vulnbell schema <name> --json`; the test suite compares every published schema with its Rust type. Do not edit generated schemas by hand.

Parser and connector changes need success and failure fixtures. Sandbox changes need `cargo test --test sandbox_live --locked -- --ignored --nocapture` with Microsandbox ready. Agent tests that need provider access are optional local tests.

Never run monitored code on the host. Keep credentials, reports, databases, and downloaded artifacts outside the repository. Migrations must support older versions or reject them with a clear error.
