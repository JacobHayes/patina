use super::*;
use patina_dst_native_shim::registry::{Os, SYMBOLS, SymbolStatus};

/// A function the recipe tells configure is missing must be one the shim
/// does not serve on Linux, where Python guests build (in any of glibc's
/// spellings of it):
/// once the shim models one, CPython should call it, so the recipe stops
/// hiding it.
#[test]
fn the_recipe_hides_only_functions_the_shim_does_not_serve() {
    let served: Vec<&str> = SYMBOLS
        .iter()
        .filter(|row| row.platform.defines_on(Os::Linux))
        .filter(|row| matches!(row.status, SymbolStatus::Modeled | SymbolStatus::Partial))
        .map(|row| row.name)
        .collect();
    let hidden: Vec<&str> = RECIPE
        .functions
        .iter()
        .flat_map(|(_, functions)| functions.iter().copied())
        .filter(|function| {
            [
                function.to_string(),
                format!("{function}64"),
                format!("__{function}"),
            ]
            .iter()
            .any(|spelling| served.contains(&spelling.as_str()))
        })
        .collect();
    assert_eq!(hidden, Vec::<&str>::new());
}
