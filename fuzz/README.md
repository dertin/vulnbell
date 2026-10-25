# Parser fuzzing

Seed the generated corpus from the versioned format fixtures, then use the installed nightly toolchain and cargo-fuzz:

```sh
mkdir -p fuzz/corpus/lock_parsers
cp tests/fixtures/workspace/*/* fuzz/corpus/lock_parsers/
cargo +nightly fuzz run lock_parsers -- -max_total_time=20 -max_len=4096
```

The target feeds each bounded input into each supported lock/SBOM parser. Generated corpus, artifacts and target files are ignored; keep regression fixtures in `tests/fixtures` if a crash is found. A bounded run does not prove parser completeness.
