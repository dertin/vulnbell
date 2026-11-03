use super::*;

type CargoDependencies = HashSet<(String, Option<String>)>;
type JsonKeyLines = HashMap<String, Option<usize>>;

#[derive(Default)]
pub(super) struct CargoGraph {
    counts: HashMap<String, usize>,
    roots: HashMap<(String, String), Option<CargoDependencies>>,
}

impl CargoGraph {
    fn parse(lock: &toml::Value) -> Option<Self> {
        let packages = lock.get("package")?.as_array()?;
        let mut graph = Self::default();
        for package in packages {
            let name = package.get("name")?.as_str()?;
            *graph.counts.entry(name.to_owned()).or_default() += 1;
            if package.get("source").is_some() {
                continue;
            }
            let version = package.get("version")?.as_str()?.to_owned();
            let mut dependencies = HashSet::new();
            if let Some(values) = package.get("dependencies") {
                for value in values.as_array()? {
                    let mut fields = value.as_str()?.split_whitespace();
                    let name = fields.next()?.to_owned();
                    let version = fields
                        .next()
                        .filter(|value| !value.starts_with('('))
                        .map(str::to_owned);
                    dependencies.insert((name, version));
                }
            }
            graph
                .roots
                .entry((name.to_owned(), version))
                .and_modify(|root| *root = None)
                .or_insert(Some(dependencies));
        }
        Some(graph)
    }

    pub(super) fn depends_on(
        &self,
        member: &str,
        member_version: &str,
        dependency: &str,
        version: &str,
    ) -> bool {
        let Some(Some(dependencies)) = self
            .roots
            .get(&(member.to_owned(), member_version.to_owned()))
        else {
            return false;
        };
        dependencies.contains(&(dependency.to_owned(), Some(version.to_owned())))
            || self.counts.get(dependency) == Some(&1)
                && dependencies.contains(&(dependency.to_owned(), None))
    }
}

#[derive(Default)]
pub(super) struct Files {
    bytes: HashMap<FileKey, Option<Rc<Vec<u8>>>>,
    toml: HashMap<FileKey, Option<Rc<toml::Value>>>,
    json: HashMap<FileKey, Option<Rc<serde_json::Value>>>,
    pub(super) cargo_lines: HashMap<FileKey, Option<Rc<Vec<CargoLine>>>>,
    json_keys: HashMap<FileKey, Option<Rc<JsonKeyLines>>>,
    cargo_graphs: HashMap<FileKey, Option<Rc<CargoGraph>>>,
    digests: HashMap<FileKey, Option<String>>,
    pub(super) total: usize,
    total_lines: usize,
    total_json_keys: usize,
}

impl Files {
    pub(super) fn digest(&mut self, root: &str, path: &str) -> Option<String> {
        let key = (root.to_owned(), path.to_owned());
        if let Some(digest) = self.digests.get(&key) {
            return digest.clone();
        }
        let digest = self.bytes(root, path).map(|bytes| crate::digest(&bytes));
        self.digests.insert(key, digest.clone());
        digest
    }

    pub(super) fn bytes(&mut self, root: &str, path: &str) -> Option<Rc<Vec<u8>>> {
        let key = (root.to_owned(), path.to_owned());
        if let Some(bytes) = self.bytes.get(&key) {
            return bytes.clone();
        }
        if self.bytes.len() >= FILE_COUNT_LIMIT {
            return None;
        }
        let read = || -> Option<Vec<u8>> {
            let file = crate::discovery::open_file(root, path).ok()?;
            let metadata = file.metadata().ok()?;
            if !metadata.is_file()
                || metadata.len() > FILE_LIMIT
                || metadata.len() > (TOTAL_LIMIT - self.total) as u64
            {
                return None;
            }
            let mut bytes = Vec::new();
            file.take(FILE_LIMIT + 1).read_to_end(&mut bytes).ok()?;
            (bytes.len() <= TOTAL_LIMIT - self.total
                && bytes.len() as u64 <= FILE_LIMIT
                && !bytes.contains(&0))
            .then_some(bytes)
        };
        let bytes = read().map(|bytes| {
            self.total += bytes.len();
            Rc::new(bytes)
        });
        self.bytes.insert(key, bytes.clone());
        bytes
    }

    pub(super) fn toml(&mut self, root: &str, path: &str) -> Option<Rc<toml::Value>> {
        let key = (root.to_owned(), path.to_owned());
        if let Some(value) = self.toml.get(&key) {
            return value.clone();
        }
        let parsed = self.bytes(root, path).and_then(|bytes| {
            let text = std::str::from_utf8(&bytes).ok()?;
            Some(Rc::new(toml::from_str(text).ok()?))
        });
        self.toml.insert(key, parsed.clone());
        parsed
    }

    pub(super) fn json(&mut self, root: &str, path: &str) -> Option<Rc<serde_json::Value>> {
        let key = (root.to_owned(), path.to_owned());
        if let Some(value) = self.json.get(&key) {
            return value.clone();
        }
        let parsed = self
            .bytes(root, path)
            .and_then(|bytes| Some(Rc::new(serde_json::from_slice(&bytes).ok()?)));
        self.json.insert(key, parsed.clone());
        parsed
    }

    pub(super) fn cargo_lines(&mut self, root: &str, path: &str) -> Option<Rc<Vec<CargoLine>>> {
        let key = (root.to_owned(), path.to_owned());
        if let Some(lines) = self.cargo_lines.get(&key) {
            return lines.clone();
        }
        let parsed = self.bytes(root, path).and_then(|bytes| {
            let text = std::str::from_utf8(&bytes).ok()?;
            if text.contains("\"\"\"") || text.contains("'''") {
                return None;
            }
            let mut lines = Vec::new();
            let mut offset = 0;
            let mut workspace = None;
            for line in text.split_inclusive('\n') {
                if self.total_lines + lines.len() >= LINE_COUNT_LIMIT {
                    return None;
                }
                let trimmed = line.trim();
                if trimmed.starts_with('[') {
                    let header = trimmed.split('#').next().unwrap_or_default().trim();
                    workspace = match header {
                        "[workspace.dependencies]" => Some(true),
                        "[dependencies]" | "[dev-dependencies]" | "[build-dependencies]" => {
                            Some(false)
                        }
                        _ => None,
                    };
                }
                lines.push(CargoLine {
                    start: offset,
                    end: offset + line.len(),
                    workspace,
                });
                offset += line.len();
            }
            self.total_lines += lines.len();
            Some(Rc::new(lines))
        });
        self.cargo_lines.insert(key, parsed.clone());
        parsed
    }

    pub(super) fn json_key_line(&mut self, root: &str, path: &str, name: &str) -> Option<usize> {
        let key = (root.to_owned(), path.to_owned());
        if !self.json_keys.contains_key(&key) {
            let parsed = self.bytes(root, path).and_then(|bytes| {
                let mut keys = HashMap::<String, Option<usize>>::new();
                let mut index = 0;
                let mut line = 1;
                while index < bytes.len() {
                    if bytes[index] == b'\n' {
                        line += 1;
                    }
                    if bytes[index] != b'"' {
                        index += 1;
                        continue;
                    }
                    let start = index;
                    index += 1;
                    while index < bytes.len() && bytes[index] != b'"' {
                        if bytes[index] == b'\\' {
                            index += 1;
                        }
                        index += 1;
                    }
                    if index >= bytes.len() {
                        return None;
                    }
                    let end = index + 1;
                    let mut next = end;
                    while next < bytes.len() && bytes[next].is_ascii_whitespace() {
                        next += 1;
                    }
                    if bytes.get(next) == Some(&b':') {
                        if self.total_json_keys + keys.len() >= LINE_COUNT_LIMIT {
                            return None;
                        }
                        let name: String = serde_json::from_slice(&bytes[start..end]).ok()?;
                        keys.entry(name)
                            .and_modify(|line| *line = None)
                            .or_insert(Some(line));
                    }
                    index = end;
                }
                self.total_json_keys += keys.len();
                Some(Rc::new(keys))
            });
            self.json_keys.insert(key.clone(), parsed);
        }
        self.json_keys
            .get(&key)?
            .as_ref()?
            .get(name)
            .copied()
            .flatten()
    }

    pub(super) fn cargo_graph(&mut self, root: &str, path: &str) -> Option<Rc<CargoGraph>> {
        let key = (root.to_owned(), path.to_owned());
        if let Some(graph) = self.cargo_graphs.get(&key) {
            return graph.clone();
        }
        let graph = self
            .toml(root, path)
            .and_then(|lock| CargoGraph::parse(&lock).map(Rc::new));
        self.cargo_graphs.insert(key, graph.clone());
        graph
    }
}
