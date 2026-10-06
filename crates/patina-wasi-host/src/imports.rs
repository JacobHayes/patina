//! The only registration path for guest imports counts before invoking a body.

use crate::Preview1Host;
use std::collections::BTreeSet;
use wasmi::{Caller, Engine, Error, Instance, Linker, Module, Store, WasmRet, WasmTy};

/// Registration modules cannot access the raw linker or register an uncounted
/// wrapper. The same name identifies both the import and its depth-report row.
pub(super) struct Imports {
    linker: Linker<Preview1Host>,
    names: BTreeSet<&'static str>,
}

/// Only the registration adapter can mint a claim to increment the counter.
pub(super) struct HostcallClaim {
    name: &'static str,
}

impl HostcallClaim {
    pub(super) fn name(self) -> &'static str {
        self.name
    }
}

impl Imports {
    pub(super) fn new(engine: &Engine) -> Self {
        Self {
            linker: Linker::new(engine),
            names: BTreeSet::new(),
        }
    }

    pub(super) fn func_wrap<Params, Results>(
        &mut self,
        module: &str,
        name: &'static str,
        body: impl CountedBody<Params, Results>,
    ) -> Result<(), Error> {
        if !self.names.insert(name) {
            return Err(Error::new(format!(
                "duplicate hostcall report name {name:?} in import module {module:?}"
            )));
        }
        body.register(&mut self.linker, module, name)
    }

    pub(super) fn instantiate_and_start(
        &self,
        store: &mut Store<Preview1Host>,
        module: &Module,
    ) -> Result<Instance, Error> {
        self.linker.instantiate_and_start(store, module)
    }
}

// Sealed so a registration module cannot supply its own uncounted adapter.
mod sealed {
    pub trait Sealed<Params, Results> {}
}

pub(super) trait CountedBody<Params, Results>: sealed::Sealed<Params, Results> {
    fn register(
        self,
        linker: &mut Linker<Preview1Host>,
        module: &str,
        name: &'static str,
    ) -> Result<(), Error>;
}

macro_rules! counted_body {
    ($($param:ident),*) => {
        impl<F, R, $($param,)*> sealed::Sealed<($($param,)*), R> for F
        where
            F: Fn(Caller<'_, Preview1Host>, $($param),*) -> R + Send + Sync + 'static,
            $($param: WasmTy,)*
            R: WasmRet,
        {}

        impl<F, R, $($param,)*> CountedBody<($($param,)*), R> for F
        where
            F: Fn(Caller<'_, Preview1Host>, $($param),*) -> R + Send + Sync + 'static,
            $($param: WasmTy,)*
            R: WasmRet,
        {
            #[allow(non_snake_case)]
            fn register(self, linker: &mut Linker<Preview1Host>, module: &str, name: &'static str)
            -> Result<(), Error> {
                linker.func_wrap(module, name, move |mut caller: Caller<'_, Preview1Host>, $($param: $param),*| {
                    caller.data_mut().count_hostcall(HostcallClaim { name });
                    self(caller, $($param),*)
                })?;
                Ok(())
            }
        }
    };
}

counted_body!();
counted_body!(A);
counted_body!(A, B);
counted_body!(A, B, C);
counted_body!(A, B, C, D);
counted_body!(A, B, C, D, E);
counted_body!(A, B, C, D, E, F0);
counted_body!(A, B, C, D, E, F0, G);
counted_body!(A, B, C, D, E, F0, G, H);
counted_body!(A, B, C, D, E, F0, G, H, I);

#[cfg(test)]
mod tests {
    use super::*;

    // Class pairing: all registration goes through Imports, which rejects
    // duplicate report keys even when Wasmi would accept distinct modules.
    #[test]
    fn report_names_are_unique_across_import_modules() {
        let engine = Engine::default();
        let mut imports = Imports::new(&engine);
        imports
            .func_wrap("first", "shared_name", |_: Caller<'_, Preview1Host>| ())
            .unwrap();
        let error = imports
            .func_wrap("second", "shared_name", |_: Caller<'_, Preview1Host>| ())
            .unwrap_err();
        assert!(error.to_string().contains("duplicate hostcall report name"));
        assert!(error.to_string().contains("shared_name"));
    }
}
