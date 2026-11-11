//! The dimensions `campaign --vary` draws per generation: the exploration
//! dimensions and the fault planes.

use patina_dst_runtime::FaultKnob;

/// One fault plane: the run knobs whose flags share a word (`--fs-*`,
/// `--net-*`, `--*-crash-permille`, ...), which is also the leading component
/// of the swarm class tokens of the knobs a campaign draws (`fs_error`,
/// `net_drop`, ...). The name is that word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultPlane {
    Fs,
    Net,
    Dns,
    Entropy,
    Sleep,
    Epoch,
    /// Native only: a crash and restart at two drawn rates per crash point,
    /// the machine's and the process's.
    Crash,
}

impl FaultPlane {
    /// Every plane, in canonical order: the order a subset is recorded in.
    pub const ALL: [FaultPlane; 7] = [
        FaultPlane::Fs,
        FaultPlane::Net,
        FaultPlane::Dns,
        FaultPlane::Entropy,
        FaultPlane::Sleep,
        FaultPlane::Epoch,
        FaultPlane::Crash,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            FaultPlane::Fs => "fs",
            FaultPlane::Net => "net",
            FaultPlane::Dns => "dns",
            FaultPlane::Entropy => "entropy",
            FaultPlane::Sleep => "sleep",
            FaultPlane::Epoch => "epoch",
            FaultPlane::Crash => "crash",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|plane| plane.name() == name)
    }

    const fn bit(self) -> u8 {
        1 << self as u8
    }
}

/// `--vary buggify`: the buggify activation and firing rates.
const VARY_BUGGIFY: &str = "buggify";
/// `--vary sched-pct`: the PCT bug depth.
const VARY_SCHED_PCT: &str = "sched-pct";
/// `--vary yield-stride`: an instrumented artifact's yield stride.
const VARY_YIELD_STRIDE: &str = "yield-stride";
/// `--vary faults`: every fault plane.
const VARY_FAULTS: &str = "faults";

/// The members of the `--vary` grammar in canonical order: the exploration
/// dimensions, `faults` for every plane, and each plane.
pub(crate) const VARY_NAMES: &[&str] = &{
    let mut names = [""; 4 + FaultPlane::ALL.len()];
    names[0] = VARY_BUGGIFY;
    names[1] = VARY_SCHED_PCT;
    names[2] = VARY_YIELD_STRIDE;
    names[3] = VARY_FAULTS;
    let mut i = 0;
    while i < FaultPlane::ALL.len() {
        names[4 + i] = FaultPlane::ALL[i].name();
        i += 1;
    }
    names
};

/// What a campaign draws per generation (`--vary`, spec key `vary`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Vary {
    pub buggify: bool,
    pub sched_pct: bool,
    pub yield_stride: bool,
    pub faults: FaultPlanes,
}

impl Vary {
    /// The set a `--vary` list names. Refuses an unknown name, naming the
    /// valid ones.
    pub fn from_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<Self, String> {
        let mut vary = Vary::default();
        for name in names {
            match name {
                VARY_BUGGIFY => vary.buggify = true,
                VARY_SCHED_PCT => vary.sched_pct = true,
                VARY_YIELD_STRIDE => vary.yield_stride = true,
                VARY_FAULTS => vary.faults = FaultPlanes::ALL,
                plane => {
                    let plane = FaultPlane::from_name(plane).ok_or_else(|| {
                        format!(
                            "unknown --vary dimension {name:?}; expected one or more of {}",
                            VARY_NAMES.join(", ")
                        )
                    })?;
                    vary.faults.0 |= plane.bit();
                }
            }
        }
        Ok(vary)
    }

    /// The canonical names: `faults` when every plane is drawn, else each
    /// drawn plane.
    pub fn names(self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.buggify {
            names.push(VARY_BUGGIFY);
        }
        if self.sched_pct {
            names.push(VARY_SCHED_PCT);
        }
        if self.yield_stride {
            names.push(VARY_YIELD_STRIDE);
        }
        if self.faults == FaultPlanes::ALL {
            names.push(VARY_FAULTS);
        } else {
            names.extend(self.faults.planes().map(FaultPlane::name));
        }
        names
    }
}

/// The plane whose selection gates a knob's band, or `None` for a knob no plane
/// selects. Exhaustive, so a new knob is a decision rather than an omission.
const fn knob_plane(knob: FaultKnob) -> Option<FaultPlane> {
    match knob {
        FaultKnob::FsErrorPermille | FaultKnob::FsShortPermille | FaultKnob::FsLatencyNanos => {
            Some(FaultPlane::Fs)
        }
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
        FaultKnob::MachineCrashPermille | FaultKnob::ProcessCrashPermille => {
            Some(FaultPlane::Crash)
        }
        // The host table is workload, forwarded whichever planes are drawn.
        FaultKnob::DnsEntry => None,
        // A target names one operation of one guest's sequence: no plane can
        // draw it.
        FaultKnob::FsErrorAt => None,
    }
}

/// The fault planes a campaign draws: none by default, every plane under
/// `--vary faults`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FaultPlanes(u8);

impl FaultPlanes {
    pub const ALL: Self = Self({
        let mut bits = 0;
        let mut i = 0;
        while i < FaultPlane::ALL.len() {
            bits |= FaultPlane::ALL[i].bit();
            i += 1;
        }
        bits
    });

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
}
