//! Coverage symbol lookup and attribution.

use super::*;

#[derive(Clone, Debug)]
struct FunctionSymbol {
    address: u64,
    end: u64,
    symbol: String,
    demangled: String,
}

#[derive(Clone, Debug)]
struct SymbolTable {
    anchor: u64,
    functions: Vec<FunctionSymbol>,
}

fn read_symbol_table(binary: &Path) -> Result<SymbolTable, CliError> {
    let bytes = fs::read(binary).map_err(|error| {
        CliError(format!(
            "failed to read binary {} for coverage symbolization: {error}",
            binary.display()
        ))
    })?;
    let file = object::File::parse(&*bytes).map_err(|error| {
        CliError(format!(
            "failed to parse binary {} for coverage symbolization: {error}",
            binary.display()
        ))
    })?;
    let mut anchor = None;
    let mut functions = BTreeMap::<u64, FunctionSymbol>::new();
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        let Ok(name) = symbol.name() else {
            continue;
        };
        let normalized = name.trim_start_matches('_');
        if normalized == "patina_yield_point" {
            anchor = Some(symbol.address());
        }
        if symbol.is_undefined() || symbol.kind() != SymbolKind::Text || symbol.address() == 0 {
            continue;
        }
        let demangled = demangle_symbol(name);
        let size = symbol.size();
        let address = symbol.address();
        let end = if size == 0 {
            address
        } else {
            address.saturating_add(size)
        };
        functions.entry(address).or_insert(FunctionSymbol {
            address,
            end,
            symbol: name.to_string(),
            demangled,
        });
    }
    let anchor = anchor.ok_or_else(|| {
        CliError(format!(
            "coverage symbolization could not find nm anchor symbol patina_yield_point in {}; is this a native --yield-points binary?",
            binary.display()
        ))
    })?;
    let mut functions: Vec<_> = functions.into_values().collect();
    functions.sort_by_key(|function| function.address);
    let addresses: Vec<u64> = functions.iter().map(|function| function.address).collect();
    for (index, function) in functions.iter_mut().enumerate() {
        if function.end <= function.address {
            if let Some(next) = addresses.get(index + 1).copied() {
                function.end = next;
            } else {
                function.end = u64::MAX;
            }
        }
    }
    Ok(SymbolTable { anchor, functions })
}

fn demangle_symbol(name: &str) -> String {
    if let Ok(demangled) = rustc_demangle::try_demangle(name) {
        return format!("{demangled:#}");
    }
    if let Some(stripped) = name.strip_prefix('_')
        && let Ok(demangled) = rustc_demangle::try_demangle(stripped)
    {
        return format!("{demangled:#}");
    }
    name.trim_start_matches('_').to_string()
}

impl SymbolTable {
    fn function_for_pc(&self, pc: u64) -> Option<&FunctionSymbol> {
        let index = self
            .functions
            .partition_point(|function| function.address <= pc);
        let function = self.functions.get(index.checked_sub(1)?)?;
        (pc < function.end).then_some(function)
    }
}

#[derive(Clone, Debug)]
struct EdgeAttribution {
    crate_name: String,
    module: String,
    covered: bool,
    groups: Vec<String>,
}

impl RollupLeaf for EdgeAttribution {
    fn crate_name(&self) -> &str {
        &self.crate_name
    }

    fn module(&self) -> &str {
        &self.module
    }

    fn groups(&self) -> &[String] {
        &self.groups
    }

    fn bucket(&self) -> &str {
        if self.covered { "covered" } else { "uncovered" }
    }

    fn is_gap(&self) -> bool {
        !self.covered
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct CoverageStats {
    pub(super) edges_total: u64,
    pub(super) edges_covered: u64,
    pub(super) hits_total: u64,
}

impl CoverageStats {
    fn add(&mut self, covered: bool, hits: u64) {
        self.edges_total += 1;
        if covered {
            self.edges_covered += 1;
        }
        self.hits_total = self.hits_total.saturating_add(hits);
    }

    pub(super) fn covered_permille(&self) -> u64 {
        permille(self.edges_covered, self.edges_total)
    }
}

#[derive(Clone, Debug)]
pub(super) struct CoverageReportTree {
    pub(super) rollup: Rollup,
    pub(super) crates: BTreeMap<String, CoverageStats>,
    pub(super) modules: BTreeMap<(String, String), CoverageStats>,
    pub(super) functions: BTreeMap<String, CoverageStats>,
}

pub(super) fn symbolize_coverage(
    binary: &Path,
    data: &CoverageData,
) -> Result<CoverageReportTree, CliError> {
    if data.hits.len() != data.deltas.len() {
        return Err(CliError(format!(
            "coverage input has {} hit counters but {} site deltas",
            data.hits.len(),
            data.deltas.len()
        )));
    }
    let symbols = read_symbol_table(binary)?;
    let mut edges = Vec::with_capacity(data.hits.len());
    let mut crates = BTreeMap::<String, CoverageStats>::new();
    let mut modules = BTreeMap::<(String, String), CoverageStats>::new();
    let mut functions = BTreeMap::<String, CoverageStats>::new();
    for (index, (&hits, &delta)) in data.hits.iter().zip(&data.deltas).enumerate() {
        let covered = hits != 0;
        let (static_pc, function) = if delta == 0 && !covered {
            (None, None)
        } else {
            let pc_i128 = i128::from(symbols.anchor) + i128::from(delta);
            if !(0..=i128::from(u64::MAX)).contains(&pc_i128) {
                return Err(CliError(format!(
                    "coverage edge {index} static pc is out of range: anchor={} delta={delta}",
                    symbols.anchor
                )));
            }
            let pc = pc_i128 as u64;
            (Some(pc), symbols.function_for_pc(pc))
        };
        let (crate_name, module, function_path, symbol_name) = function.map_or_else(
            || {
                (
                    "<unknown>".to_string(),
                    "<unknown>".to_string(),
                    "<unknown>".to_string(),
                    "<unknown>".to_string(),
                )
            },
            |function| {
                let parsed = parse_symbol_path(&function.demangled);
                (
                    parsed.crate_name,
                    parsed.module,
                    parsed.function_path,
                    function.symbol.clone(),
                )
            },
        );
        crates
            .entry(crate_name.clone())
            .or_default()
            .add(covered, hits);
        modules
            .entry((crate_name.clone(), module.clone()))
            .or_default()
            .add(covered, hits);
        functions
            .entry(function_path.clone())
            .or_default()
            .add(covered, hits);
        let _ = (symbol_name, static_pc);
        edges.push(EdgeAttribution {
            crate_name,
            module,
            covered,
            groups: Vec::new(),
        });
    }
    let rollup = build_rollup(&edges, COVERED_BUCKETS);
    Ok(CoverageReportTree {
        rollup,
        crates,
        modules,
        functions,
    })
}

struct ParsedSymbolPath {
    crate_name: String,
    module: String,
    function_path: String,
}

fn parse_symbol_path(demangled: &str) -> ParsedSymbolPath {
    let cleaned = demangled
        .split("::h")
        .next()
        .unwrap_or(demangled)
        .trim()
        .to_string();
    let grouping_path = grouping_path_for_symbol(&cleaned);
    let parts: Vec<&str> = grouping_path
        .split("::")
        .map(|part| part.trim_matches(|c| c == '<' || c == '>' || c == '&' || c == '[' || c == ']'))
        .filter(|part| !part.is_empty())
        .collect();
    if parts.is_empty() {
        return ParsedSymbolPath {
            crate_name: "<unknown>".to_string(),
            module: "<unknown>".to_string(),
            function_path: cleaned,
        };
    }
    let crate_name = if parts.len() == 1 && primitive_type(parts[0]) {
        "core".to_string()
    } else {
        parts[0].to_string()
    };
    let module = if parts.len() <= 1 {
        crate_name.clone()
    } else {
        parts[..parts.len() - 1].join("::")
    };
    ParsedSymbolPath {
        crate_name,
        module,
        function_path: cleaned,
    }
}

fn primitive_type(part: &str) -> bool {
    matches!(
        part,
        "bool"
            | "char"
            | "str"
            | "u8"
            | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "usize"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "i128"
            | "isize"
    )
}

fn grouping_path_for_symbol(symbol: &str) -> &str {
    let symbol = symbol
        .trim_start_matches("&mut ")
        .trim_start_matches("mut ")
        .trim_start_matches("const ");
    if symbol.starts_with('[') || symbol.starts_with('*') {
        return "core";
    }
    let Some(inner) = symbol
        .strip_prefix('<')
        .and_then(|rest| rest.split('>').next())
    else {
        return symbol;
    };
    let inner = inner.trim();
    if let Some((left, right)) = inner.split_once(" as ") {
        let left = left.trim();
        if left.contains("::") && !left.starts_with('*') && left != "()" {
            return normalize_grouping_path(left);
        }
        return normalize_grouping_path(right.trim());
    }
    normalize_grouping_path(inner)
}

fn normalize_grouping_path(path: &str) -> &str {
    let path = path
        .trim_start_matches("&mut ")
        .trim_start_matches("mut ")
        .trim_start_matches("const ")
        .trim_start_matches('<')
        .trim_start();
    if path.starts_with('*') {
        return "core";
    }
    if let Some(stripped) = path.strip_prefix('[') {
        let stripped = stripped.trim_start_matches('&');
        if stripped.contains("::") {
            return stripped;
        }
        return "core";
    }
    path
}
