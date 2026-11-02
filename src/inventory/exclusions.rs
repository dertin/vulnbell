use std::path::Path;

pub(crate) const EXCLUDED_DIRECTORIES: &[&str] = &[
    ".git",
    "node_modules",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    ".gradle",
    ".terraform",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".next",
    ".nuxt",
    ".sqlx",
    ".cache",
    "dist",
    "build",
    "target",
    "bower_components",
    ".pnpm-store",
    ".bundle",
];

pub(crate) fn excluded_directory(name: &str) -> bool {
    EXCLUDED_DIRECTORIES.contains(&name) || name == ".codegraph" || name.starts_with(".codegraph-")
}

pub(crate) fn excluded_path(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(component, std::path::Component::Normal(name) if excluded_directory(&name.to_string_lossy()))
    })
}
