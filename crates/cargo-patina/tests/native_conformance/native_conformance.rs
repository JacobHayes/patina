//! Independent, filterable tests generated from the scenario catalog.

#[cfg(test)]
mod tests {
    use crate::conform;
    use patina_dst_conformance::catalog;

    // A new catalog row also declares its acceptance test; architecture cfgs
    // travel with the row rather than living in a second hand-maintained list.
    macro_rules! conformance_tests {
        ($( $(#[$attr:meta])* $id:ident => $family:ident::$case:ident, )*) => {
            $(
                $(#[$attr])*
                #[test]
                fn $id() {
                    conform(catalog::ScenarioId::$id.scenario().name);
                }
            )*
        };
    }
    patina_dst_conformance::for_each_scenario!(conformance_tests);
}
