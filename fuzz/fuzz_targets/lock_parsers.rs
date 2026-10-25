#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 64 * 1024 { return; }
    for filename in ["Cargo.lock", "composer.lock", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bom.json"] {
        let _ = vulnbell::inventory::parse_lock(filename, bytes);
    }
});
