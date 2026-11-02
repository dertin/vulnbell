# Contribute

You need Rust 1.90+ and a C compiler. Use concrete types, explicit states, bounded processes, and errors that explain what failed.

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo package --locked --allow-dirty
```

Rust types define the data contracts. Generate schemas with `vulnbell schema <name> --json`; the test suite compares every published schema with its Rust type. Do not edit generated schemas by hand.

PDF layout changes also need `cargo test --lib output::pdf::tests --locked -- --ignored`, with a Chromium-based browser and Poppler (`pdfinfo` and `pdftotext`).

The sample report uses fictional data. Regenerate its Markdown with `VULNBELL_UPDATE_EXAMPLE=1 cargo test --test example_report --locked`. To regenerate its PDF, remove `examples/report.pdf` and run `VULNBELL_EXAMPLE_PDF="$PWD/examples/report.pdf" cargo test --test example_report --locked`. The CLI does not overwrite existing PDFs.

Parser and connector changes need success and failure fixtures. Sandbox changes need `cargo test --test sandbox_live --locked -- --ignored --nocapture` with Microsandbox ready. Agent tests that need provider access are optional local tests.

Run `python3 -I -m unittest discover -s tests -p test_manifest_reader.py` for the optional structured-data helper. Discovery changes need resumable inventory, stale/fabricated evidence, source coverage and permission-boundary tests. Missing evidence must remain partial; imported agent observations cannot attest deployment or authorize active tests.

Runner adapters implement the internal `AgentAdapter` contract in `src/runners/`. A new adapter needs a typed `AdapterConfig` variant, registry entry, exact supported-version check, effective public-research and tool-free permission checks, bounded structured output, failure tests, and one live ignored acceptance test. Update the generated runner schema and [runner documentation](docs/runners.md) with only verified support.

Never run monitored code on the host. Keep credentials, real reports, databases, and downloaded artifacts outside the repository. Use current contracts only and reject incompatible state without changing its data.
