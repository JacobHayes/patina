//! Workspace source inventory and scan caching.

use super::*;
const CACHE_SCHEMA: &str = "patina.sites-cache/v1";
pub(super) const RECOGNIZER_TABLE_VERSION: &str = "sites-sca-v1";

#[derive(Clone, Debug)]
pub(super) struct ScanPackage {
    pub(super) name: String,
    pub(super) root: PathBuf,
    pub(super) targets: Vec<TargetHint>,
}

#[derive(Clone, Debug)]
pub(super) struct TargetHint {
    pub(super) src_path: PathBuf,
    pub(super) name: String,
    pub(super) context: ContextKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ContextKind {
    Src,
    Test,
    Example,
    Bench,
}

impl ContextKind {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Src => "src",
            Self::Test => "test",
            Self::Example => "example",
            Self::Bench => "bench",
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct SourceFile {
    path: PathBuf,
    pub(super) rel_path: String,
    pub(super) crate_name: String,
    pub(super) module: String,
    pub(super) context: ContextKind,
}

#[derive(Clone, Debug)]
pub(super) struct StaticScan {
    pub(super) workspace_root: PathBuf,
    pub(crate) sites: Vec<SiteRecord>,
    pub(super) files_scanned: usize,
    pub(super) files_unparsed: usize,
    pub(super) unparsed: Vec<UnparsedFile>,
    pub(super) cache_state: CacheState,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct UnparsedFile {
    file: String,
    error: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CacheState {
    Hit,
    Cold,
}

impl CacheState {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            CacheState::Hit => "hit",
            CacheState::Cold => "cold",
        }
    }
}

#[derive(Serialize, Deserialize)]
struct SitesCache {
    schema: String,
    recognizer_version: String,
    files: BTreeMap<String, CachedFile>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct CachedFile {
    pub(super) sha256: String,
    pub(super) sites: Vec<SiteRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) error: Option<String>,
}

pub(super) fn scan_current_workspace(use_cache: bool) -> Result<StaticScan, CliError> {
    let (workspace_root, packages) = workspace_packages()?;
    scan_packages(workspace_root, packages, use_cache)
}

fn workspace_packages() -> Result<(PathBuf, Vec<ScanPackage>), CliError> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let output = Command::new(cargo)
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| CliError(format!("failed to run cargo metadata: {error}")))?;
    if !output.status.success() {
        return Err(CliError(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let metadata: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| CliError(format!("cargo metadata returned invalid JSON: {error}")))?;
    let workspace_root = metadata
        .get("workspace_root")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| CliError("cargo metadata omitted workspace_root".into()))?;
    let members: BTreeSet<String> = metadata
        .get("workspace_members")
        .and_then(Value::as_array)
        .ok_or_else(|| CliError("cargo metadata omitted workspace_members".into()))?
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect();
    let mut packages = Vec::new();
    for package in metadata
        .get("packages")
        .and_then(Value::as_array)
        .ok_or_else(|| CliError("cargo metadata omitted packages".into()))?
    {
        let id = package
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| CliError("cargo metadata package omitted id".into()))?;
        if !members.contains(id) {
            continue;
        }
        let name = package
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| CliError(format!("cargo metadata package {id} omitted name")))?
            .to_string();
        let manifest = package
            .get("manifest_path")
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .ok_or_else(|| {
                CliError(format!(
                    "cargo metadata package {name} omitted manifest_path"
                ))
            })?;
        let root = manifest.parent().map(Path::to_path_buf).ok_or_else(|| {
            CliError(format!(
                "manifest path has no parent for package {name}: {}",
                manifest.display()
            ))
        })?;
        let mut targets = Vec::new();
        if let Some(array) = package.get("targets").and_then(Value::as_array) {
            for target in array {
                let Some(src_path) = target.get("src_path").and_then(Value::as_str) else {
                    continue;
                };
                let Some(target_name) = target.get("name").and_then(Value::as_str) else {
                    continue;
                };
                let Some(kinds) = target.get("kind").and_then(Value::as_array) else {
                    continue;
                };
                let context = if kinds.iter().any(|kind| kind.as_str() == Some("test")) {
                    ContextKind::Test
                } else if kinds.iter().any(|kind| kind.as_str() == Some("example")) {
                    ContextKind::Example
                } else if kinds.iter().any(|kind| kind.as_str() == Some("bench")) {
                    ContextKind::Bench
                } else if kinds
                    .iter()
                    .any(|kind| matches!(kind.as_str(), Some("lib" | "bin" | "proc-macro")))
                {
                    ContextKind::Src
                } else {
                    continue;
                };
                targets.push(TargetHint {
                    src_path: PathBuf::from(src_path),
                    name: target_name.to_string(),
                    context,
                });
            }
        }
        packages.push(ScanPackage {
            name,
            root,
            targets,
        });
    }
    packages.sort_by(|left, right| left.name.cmp(&right.name));
    Ok((workspace_root, packages))
}

pub(super) fn scan_packages(
    workspace_root: PathBuf,
    packages: Vec<ScanPackage>,
    use_cache: bool,
) -> Result<StaticScan, CliError> {
    let mut files = Vec::new();
    let mut seen = BTreeSet::new();
    for package in &packages {
        collect_package_files(&workspace_root, package, &mut seen, &mut files)?;
    }
    files.sort_by(|left, right| left.rel_path.cmp(&right.rel_path));

    let cache_path = workspace_root.join(".patina/out/sites-cache.json");
    let mut cache = if use_cache {
        read_cache(&cache_path).unwrap_or_else(empty_cache)
    } else {
        empty_cache()
    };
    let mut all_cache_hits = use_cache && !files.is_empty();
    let mut updated_files = BTreeMap::new();
    let mut sites = Vec::new();
    let mut unparsed = Vec::new();

    for file in &files {
        let bytes = fs::read(&file.path).map_err(|error| {
            CliError(format!(
                "failed to read Rust source {}: {error}",
                file.path.display()
            ))
        })?;
        let sha = hex_digest(&bytes);
        let cached = use_cache
            .then(|| cache.files.remove(&file.rel_path))
            .flatten()
            .filter(|entry| entry.sha256 == sha);
        let entry = if let Some(entry) = cached {
            entry
        } else {
            all_cache_hits = false;
            scan_file(file, &bytes)
        };
        if let Some(error) = &entry.error {
            unparsed.push(UnparsedFile {
                file: file.rel_path.clone(),
                error: error.clone(),
            });
        }
        sites.extend(entry.sites.clone());
        updated_files.insert(file.rel_path.clone(), entry);
    }

    if use_cache {
        cache.files = updated_files;
        write_cache(&cache_path, &cache)?;
    }

    sites.sort_by(|left, right| {
        left.crate_name
            .cmp(&right.crate_name)
            .then(left.file.cmp(&right.file))
            .then(left.line.cmp(&right.line))
            .then(left.id.cmp(&right.id))
    });

    Ok(StaticScan {
        workspace_root,
        sites,
        files_scanned: files.len(),
        files_unparsed: unparsed.len(),
        unparsed,
        cache_state: if use_cache && all_cache_hits {
            CacheState::Hit
        } else {
            CacheState::Cold
        },
    })
}

fn empty_cache() -> SitesCache {
    SitesCache {
        schema: CACHE_SCHEMA.to_string(),
        recognizer_version: RECOGNIZER_TABLE_VERSION.to_string(),
        files: BTreeMap::new(),
    }
}

fn read_cache(path: &Path) -> Option<SitesCache> {
    let bytes = fs::read(path).ok()?;
    let cache: SitesCache = serde_json::from_slice(&bytes).ok()?;
    if cache.schema == CACHE_SCHEMA && cache.recognizer_version == RECOGNIZER_TABLE_VERSION {
        Some(cache)
    } else {
        None
    }
}

fn write_cache(path: &Path, cache: &SitesCache) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            CliError(format!(
                "failed to create sites cache dir {}: {error}",
                parent.display()
            ))
        })?;
        ensure_patina_gitignore(parent.parent().unwrap_or(parent))?;
    }
    let json = serde_json::to_vec_pretty(cache)
        .map_err(|error| CliError(format!("failed to encode sites cache: {error}")))?;
    fs::write(path, json).map_err(|error| {
        CliError(format!(
            "failed to write sites cache {}: {error}",
            path.display()
        ))
    })
}

fn ensure_patina_gitignore(patina_dir: &Path) -> Result<(), CliError> {
    let path = patina_dir.join(".gitignore");
    if path.exists() {
        let text = fs::read_to_string(&path).map_err(|error| {
            CliError(format!(
                "failed to read {} before updating generated-output ignore: {error}",
                path.display()
            ))
        })?;
        if text.lines().any(|line| line.trim() == "/out/") {
            return Ok(());
        }
        let mut updated = text;
        if !updated.ends_with('\n') {
            updated.push('\n');
        }
        updated.push_str("/out/\n");
        fs::write(&path, updated).map_err(|error| {
            CliError(format!(
                "failed to update generated-output ignore {}: {error}",
                path.display()
            ))
        })?;
    } else {
        fs::write(&path, "/out/\n").map_err(|error| {
            CliError(format!(
                "failed to write generated-output ignore {}: {error}",
                path.display()
            ))
        })?;
    }
    Ok(())
}

fn collect_package_files(
    workspace_root: &Path,
    package: &ScanPackage,
    seen: &mut BTreeSet<PathBuf>,
    out: &mut Vec<SourceFile>,
) -> Result<(), CliError> {
    let mut paths = Vec::new();
    collect_rs_paths(&package.root, &mut paths)?;
    paths.sort();
    for path in paths {
        let canonical_key = path.clone();
        if !seen.insert(canonical_key) {
            continue;
        }
        let rel_path = display_path(workspace_root, &path);
        let (module, context) = infer_module_context(package, &path);
        out.push(SourceFile {
            path,
            rel_path,
            crate_name: package.name.clone(),
            module,
            context,
        });
    }
    Ok(())
}

fn collect_rs_paths(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), CliError> {
    let entries = fs::read_dir(dir).map_err(|error| {
        CliError(format!(
            "failed to read directory {}: {error}",
            dir.display()
        ))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            CliError(format!(
                "failed to read directory entry in {}: {error}",
                dir.display()
            ))
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|error| {
            CliError(format!(
                "failed to stat directory entry {}: {error}",
                path.display()
            ))
        })?;
        if file_type.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if matches!(name.as_ref(), "target" | ".git" | ".jj" | ".patina") {
                continue;
            }
            collect_rs_paths(&path, out)?;
        } else if file_type.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("rs")
        {
            out.push(path);
        }
    }
    Ok(())
}

fn infer_module_context(package: &ScanPackage, path: &Path) -> (String, ContextKind) {
    if let Some(target) = package
        .targets
        .iter()
        .find(|target| target.src_path == path)
    {
        return (rust_ident(&target.name), target.context);
    }
    let rel = path.strip_prefix(&package.root).unwrap_or(path);
    let comps = rel
        .components()
        .filter_map(component_str)
        .collect::<Vec<_>>();
    let crate_ident = rust_ident(&package.name);
    if comps.first().copied() == Some("tests") {
        return (path_module(&comps[1..], None), ContextKind::Test);
    }
    if comps.first().copied() == Some("examples") {
        return (path_module(&comps[1..], None), ContextKind::Example);
    }
    if comps.first().copied() == Some("benches") {
        return (path_module(&comps[1..], None), ContextKind::Bench);
    }
    if comps.first().copied() == Some("src") {
        return (
            path_module(&comps[1..], Some(&crate_ident)),
            ContextKind::Src,
        );
    }
    (path_module(&comps, Some(&crate_ident)), ContextKind::Src)
}

fn component_str(component: Component<'_>) -> Option<&str> {
    match component {
        Component::Normal(value) => value.to_str(),
        _ => None,
    }
}

fn path_module(comps: &[&str], root: Option<&str>) -> String {
    let mut pieces = Vec::new();
    if let Some(root) = root {
        pieces.push(root.to_string());
    }
    for (index, comp) in comps.iter().enumerate() {
        if index + 1 == comps.len() {
            let stem = comp.strip_suffix(".rs").unwrap_or(comp);
            if matches!(stem, "lib" | "main" | "mod") {
                continue;
            }
            pieces.push(rust_ident(stem));
        } else if *comp != "src" {
            pieces.push(rust_ident(comp));
        }
    }
    if pieces.is_empty() {
        "crate".to_string()
    } else {
        pieces.join("::")
    }
}

fn rust_ident(name: &str) -> String {
    let mut out = String::new();
    for (index, ch) in name.chars().enumerate() {
        if ch == '-' || ch == '.' {
            out.push('_');
        } else if (index == 0 && (ch == '_' || ch.is_ascii_alphabetic()))
            || (index > 0 && (ch == '_' || ch.is_ascii_alphanumeric()))
        {
            out.push(ch);
        } else if index == 0 && ch.is_ascii_digit() {
            out.push('_');
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "crate".to_string()
    } else {
        out
    }
}

pub(super) fn hex_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests;
