//! The fault planes `--faults` draws, and the subset of them a campaign selects.

use patina_dst_runtime::FaultKnob;

/// One fault plane: the run knobs that share a flag prefix (`--fs-*`,
/// `--net-*`, ...), which is also the leading component of the swarm class
/// tokens of the knobs a campaign draws (`fs_error`, `net_drop`, ...). The name
/// is that prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultPlane {
    Fs,
    Net,
    Dns,
    Entropy,
    Sleep,
    Epoch,
}

impl FaultPlane {
    /// Every plane, in canonical order: the order a subset is recorded in.
    pub const ALL: [FaultPlane; 6] = [
        FaultPlane::Fs,
        FaultPlane::Net,
        FaultPlane::Dns,
        FaultPlane::Entropy,
        FaultPlane::Sleep,
        FaultPlane::Epoch,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            FaultPlane::Fs => "fs",
            FaultPlane::Net => "net",
            FaultPlane::Dns => "dns",
            FaultPlane::Entropy => "entropy",
            FaultPlane::Sleep => "sleep",
            FaultPlane::Epoch => "epoch",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|plane| plane.name() == name)
    }

    const fn bit(self) -> u8 {
        1 << self as u8
    }
}

/// The plane names in canonical order: the members of the `--faults` value
/// grammar.
pub(crate) const FAULT_PLANE_NAMES: &[&str] = &{
    let mut names = [""; FaultPlane::ALL.len()];
    let mut i = 0;
    while i < names.len() {
        names[i] = FaultPlane::ALL[i].name();
        i += 1;
    }
    names
};

/// The plane whose selection gates a knob's band, or `None` for a knob no plane
/// selects. Exhaustive, so a new knob is a decision rather than an omission.
const fn knob_plane(knob: FaultKnob) -> Option<FaultPlane> {
    match knob {
        FaultKnob::FsCrashAt
        | FaultKnob::FsTornGranularity
        | FaultKnob::FsErrorPermille
        | FaultKnob::FsShortPermille
        | FaultKnob::FsLatencyNanos => Some(FaultPlane::Fs),
        FaultKnob::NetLatencyNanos
        | FaultKnob::NetJitterNanos
        | FaultKnob::NetDropPermille
        | FaultKnob::NetDuplicatePermille
        | FaultKnob::NetConnectRefusePermille
        | FaultKnob::NetResetPermille
        | FaultKnob::NetPartition
        | FaultKnob::NetTcpBufferBytes => Some(FaultPlane::Net),
        FaultKnob::DnsFailPermille | FaultKnob::DnsLatencyNanos => Some(FaultPlane::Dns),
        FaultKnob::EntropyFailPermille => Some(FaultPlane::Entropy),
        FaultKnob::SleepJitterNanos => Some(FaultPlane::Sleep),
        FaultKnob::EpochJumpNanos => Some(FaultPlane::Epoch),
        // Opted into by `--custom-op-faults`: only the guest knows whether its
        // custom operations declare a failure shape.
        FaultKnob::CustomOpFailPermille => None,
        // The host table is workload, forwarded whichever planes are drawn.
        FaultKnob::DnsEntry => None,
    }
}

/// The fault planes a campaign draws. Empty means `--faults` is off; bare
/// `--faults` selects every plane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaultPlanes(u8);

impl FaultPlanes {
    pub const NONE: Self = Self(0);
    pub const ALL: Self = Self({
        let mut bits = 0;
        let mut i = 0;
        while i < FaultPlane::ALL.len() {
            bits |= FaultPlane::ALL[i].bit();
            i += 1;
        }
        bits
    });

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn contains(self, plane: FaultPlane) -> bool {
        self.0 & plane.bit() != 0
    }

    /// Whether this selection draws `knob`'s band. A knob no plane owns is
    /// never drawn here; its own opt-in decides.
    pub(super) fn draws(self, knob: FaultKnob) -> bool {
        knob_plane(knob).is_some_and(|plane| self.contains(plane))
    }

    /// The selected planes, in canonical order.
    pub fn planes(self) -> impl Iterator<Item = FaultPlane> {
        FaultPlane::ALL
            .into_iter()
            .filter(move |plane| self.contains(*plane))
    }

    /// The set the given plane names select. Refuses an empty list and an
    /// unknown name, naming the valid planes.
    pub fn from_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<Self, String> {
        let mut bits = 0;
        for name in names {
            let plane = FaultPlane::from_name(name).ok_or_else(|| {
                format!(
                    "unknown fault plane {name:?}; expected one or more of {}",
                    FAULT_PLANE_NAMES.join(", ")
                )
            })?;
            bits |= plane.bit();
        }
        if bits == 0 {
            return Err(format!(
                "names no fault plane; expected one or more of {}",
                FAULT_PLANE_NAMES.join(", ")
            ));
        }
        Ok(Self(bits))
    }

    /// The comma-separated spelling `--faults=` takes, in canonical order.
    pub fn cli_list(self) -> String {
        self.planes()
            .map(FaultPlane::name)
            .collect::<Vec<_>>()
            .join(",")
    }

    /// The recorded form: `false` off, `true` every plane, else the selected
    /// plane names in canonical order.
    pub(super) fn to_json(self) -> serde_json::Value {
        match self {
            Self::NONE => false.into(),
            Self::ALL => true.into(),
            subset => subset
                .planes()
                .map(|plane| serde_json::Value::from(plane.name()))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plane's name is the shared prefix of its knobs' run flags and its drawn
    /// knobs' swarm tokens, so `--faults=net` selects exactly the knobs an operator reads as
    /// the net plane in `run --help` and in a swarm report.
    #[test]
    fn a_plane_names_the_prefix_its_knobs_share() {
        for knob in FaultKnob::ALL {
            let Some(plane) = knob_plane(*knob) else {
                continue;
            };
            let meta = knob.meta();
            assert!(
                meta.flag.starts_with(&format!("--{}-", plane.name())),
                "{knob:?} is filed under {plane:?} but is spelled {}",
                meta.flag
            );
            let drawn = matches!(
                super::super::campaign_policy(*knob),
                super::super::BandPolicy::Draw(_)
            );
            if let Some(token) = meta.swarm_class.filter(|_| drawn) {
                assert!(
                    token.starts_with(&format!("{}_", plane.name())),
                    "{knob:?} is filed under {plane:?} but its swarm class is {token}"
                );
            }
        }
        for plane in FaultPlane::ALL {
            assert!(
                FaultKnob::ALL
                    .iter()
                    .any(|knob| knob_plane(*knob) == Some(plane)),
                "{plane:?} selects no knob"
            );
        }
        // Names select a set: order and repeats do not matter, and the list
        // renders in canonical order.
        let subset = FaultPlanes::from_names(["sleep", "net", "sleep"]).unwrap();
        assert_eq!(subset.cli_list(), "net,sleep");
        assert_eq!(
            FaultPlanes::from_names(FAULT_PLANE_NAMES.iter().copied()),
            Ok(FaultPlanes::ALL)
        );
        assert!(FaultPlanes::from_names(Vec::<&str>::new()).is_err());
    }
}
