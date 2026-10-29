use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

const SKILL_FILES: &[(&str, &str)] = &[
    (
        "scripts/read-manifest.py",
        include_str!("../skills/vulnbell/scripts/read-manifest.py"),
    ),
    (
        "references/discovery.md",
        include_str!("../skills/vulnbell/references/discovery.md"),
    ),
    (
        "references/safety.md",
        include_str!("../skills/vulnbell/references/safety.md"),
    ),
    ("SKILL.md", include_str!("../skills/vulnbell/SKILL.md")),
    (
        "references/upstream-research.md",
        include_str!("../skills/vulnbell/references/upstream-research.md"),
    ),
    (
        "references/profiles.md",
        include_str!("../skills/vulnbell/references/profiles.md"),
    ),
    (
        "references/investigation.md",
        include_str!("../skills/vulnbell/references/investigation.md"),
    ),
    (
        "references/automation.md",
        include_str!("../skills/vulnbell/references/automation.md"),
    ),
    (
        "references/reporting.md",
        include_str!("../skills/vulnbell/references/reporting.md"),
    ),
    (
        "references/workspace.md",
        include_str!("../skills/vulnbell/references/workspace.md"),
    ),
    (
        "examples/manual-project.yaml",
        include_str!("../examples/manual-project.yaml"),
    ),
    (
        "examples/mixed-project.yaml",
        include_str!("../examples/mixed-project.yaml"),
    ),
];
#[derive(Serialize, Deserialize)]
struct SkillManifest {
    version: String,
    files: BTreeMap<String, String>,
}
pub fn skill_directories(host: &str) -> Result<Vec<PathBuf>> {
    let home = crate::user_home()?;
    let universal = home.join(".agents/skills/vulnbell");
    match host {
        "auto" | "universal" | "codex" | "opencode" => Ok(vec![universal]),
        _ => bail!("supported hosts: auto, universal, codex, opencode"),
    }
}
pub fn install_skill(directory: &Path) -> Result<()> {
    if directory.is_symlink() {
        bail!("skill destination is a symlink");
    }
    let manifest_path = directory.join(".vulnbell-manifest.json");
    let previous: Option<SkillManifest> = if manifest_path.exists() {
        Some(serde_json::from_slice(&crate::read_limited(
            &manifest_path,
            64 * 1024,
        )?)?)
    } else {
        None
    };
    for (relative, _) in SKILL_FILES {
        let path = directory.join(relative);
        if path.exists() {
            let bytes = crate::read_limited(&path, 1024 * 1024)?;
            let hash = crate::digest(&bytes);
            if previous
                .as_ref()
                .and_then(|manifest| manifest.files.get(*relative))
                != Some(&hash)
            {
                bail!(
                    "user-modified/unmanaged skill file {}; preserve it before installing",
                    path.display()
                );
            }
        }
        if path.parent().is_some_and(Path::is_symlink) {
            bail!("skill parent is a symlink");
        }
    }
    let mut files = BTreeMap::new();
    for (relative, text) in SKILL_FILES {
        let rendered = if *relative == "SKILL.md" {
            text.replacen(
                "\n---\n\n# VulnBell",
                &format!(
                    "\nmetadata:\n  version: \"{}\"\n---\n\n# VulnBell",
                    env!("CARGO_PKG_VERSION")
                ),
                1,
            )
        } else {
            (*text).into()
        };
        crate::atomic_write(&directory.join(relative), rendered.as_bytes())?;
        files.insert((*relative).into(), crate::digest(rendered.as_bytes()));
    }
    let manifest = SkillManifest {
        version: env!("CARGO_PKG_VERSION").into(),
        files,
    };
    crate::atomic_write(&manifest_path, &serde_json::to_vec_pretty(&manifest)?)
}

#[derive(Serialize)]
pub struct SkillStatus {
    pub directory: PathBuf,
    pub installed: bool,
    pub version_aligned_and_unmodified: bool,
}
pub fn status() -> Result<Vec<SkillStatus>> {
    let mut statuses = Vec::new();
    for directory in skill_directories("auto")? {
        let manifest = crate::read_limited(&directory.join(".vulnbell-manifest.json"), 65536)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<SkillManifest>(&bytes).ok());
        let aligned = manifest.as_ref().is_some_and(|manifest| {
            manifest.version == env!("CARGO_PKG_VERSION")
                && manifest.files.iter().all(|(path, hash)| {
                    crate::read_limited(&directory.join(path), 1024 * 1024)
                        .is_ok_and(|bytes| crate::digest(&bytes) == *hash)
                })
        });
        statuses.push(SkillStatus {
            directory,
            installed: manifest.is_some(),
            version_aligned_and_unmodified: aligned,
        });
    }
    Ok(statuses)
}
