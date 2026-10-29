//! Up-front registered site families: one literal label, many runtime callers.
//!
//! A site's identity is its label, which must be known at link time so a
//! never-evaluated site can be reported. A label that varies at runtime
//! (`always!(format!("shard-{i}"), ..)`) is therefore a compile error. When the
//! same check genuinely runs for many dynamic instances, declare the family
//! once with a literal label and put the varying part in the call's detail,
//! not in the identity.

use core::fmt::Display;

/// A declared `always!` family; see [`always_family!`](crate::always_family).
pub struct AlwaysFamily {
    label: &'static str,
    site: &'static str,
}

/// A declared `sometimes!` family; see [`sometimes_family!`](crate::sometimes_family).
pub struct SometimesFamily {
    label: &'static str,
    site: &'static str,
}

/// A declared `reachable!` family; see [`reachable_family!`](crate::reachable_family).
pub struct ReachableFamily {
    label: &'static str,
    site: &'static str,
}

impl AlwaysFamily {
    #[doc(hidden)]
    pub const fn new(label: &'static str, site: &'static str) -> Self {
        Self { label, site }
    }

    /// Assert `condition` for one instance of the family. On a violation under
    /// Patina, `detail` is reported as a `violation` verdict under the family
    /// label before the run aborts, so the failing instance is named in the
    /// result. `detail` is only formatted on failure.
    #[track_caller]
    pub fn check(&self, condition: bool, detail: impl Display) {
        if !condition {
            crate::verdict(
                crate::VerdictKind::Violation,
                self.label,
                &detail.to_string(),
            );
        }
        crate::__rt::always(condition, self.label, self.site);
    }
}

impl SometimesFamily {
    #[doc(hidden)]
    pub const fn new(label: &'static str, site: &'static str) -> Self {
        Self { label, site }
    }

    /// Record whether `condition` held for one instance of the family.
    pub fn check(&self, condition: bool) {
        crate::__rt::sometimes(condition, self.label, self.site);
    }
}

impl ReachableFamily {
    #[doc(hidden)]
    pub const fn new(label: &'static str, site: &'static str) -> Self {
        Self { label, site }
    }

    /// Record that one instance of the family was reached.
    pub fn hit(&self) {
        crate::__rt::reachable(self.label, self.site);
    }
}

macro_rules! declare_family_macros {
    ($d:tt; $($macro_name:ident, $ty:ident, $descriptor:ident, $what:literal;)*) => {$(
        #[doc = concat!("Declare an up-front [`", stringify!($ty), "`]: a literal-label ", $what, " site, registered at link time, that any number of runtime callers share.")]
        ///
        /// The label must be a compile-time `&str`, exactly like the label of
        /// the matching site macro. The family is one site (the declaration's
        /// `file:line`), so it appears in `sites.json` before it runs.
        #[macro_export]
        macro_rules! $macro_name {
            ($d vis:vis $d name:ident, $d label:expr) => {
                $d vis static $d name: $d crate::$ty = {
                    $d crate::__patina_static_site!(
                        $d label,
                        ::core::concat!(::core::file!(), ":", ::core::line!()),
                        $d crate::__rt::$descriptor
                    );
                    $d crate::$ty::new(
                        $d label,
                        ::core::concat!(::core::file!(), ":", ::core::line!()),
                    )
                };
            };
        }
    )*};
}

declare_family_macros! { $;
    always_family, AlwaysFamily, STATIC_SITE_KIND_ALWAYS, "`always!`";
    sometimes_family, SometimesFamily, STATIC_SITE_KIND_SOMETIMES, "`sometimes!`";
    reachable_family, ReachableFamily, STATIC_SITE_KIND_REACHABLE, "`reachable!`";
}
