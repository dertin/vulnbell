# Development

Read the Skill contract in `skills/vulnbell/SKILL.md`. Rust types generate the schemas; tests check that the published schemas match.

Never run monitored code on the host. Active tests use Microsandbox with approval and limits. External inputs cannot grant agent permissions. Apply boring-rust-style when available.

Run `cargo fmt --all -- --check`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --all-targets --locked`, and `cargo package --locked --allow-dirty`.

If `.codegraph/` exists, use CodeGraph before searching or reading code. Do not create an index automatically.
