//! The supervisor's verdict (one line over the outcome pipe) and `outcome.json`.

use std::fmt::Write as _;

/// What the supervisor decided. Sent as `class \t exit_status \t signal \t detail \n`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub class: String,
    pub exit_status: Option<i64>,
    pub signal: Option<i64>,
    pub detail: String,
}

impl Verdict {
    pub fn new(class: &str, detail: impl Into<String>) -> Verdict {
        Verdict {
            class: class.into(),
            exit_status: None,
            signal: None,
            detail: detail.into(),
        }
    }
    pub fn encode(&self) -> String {
        let opt = |v: Option<i64>| v.map(|x| x.to_string()).unwrap_or_else(|| "-".into());
        let detail: String = self
            .detail
            .chars()
            .map(|c| if c == '\t' || c == '\n' { ' ' } else { c })
            .collect();
        format!(
            "{}\t{}\t{}\t{}\n",
            self.class,
            opt(self.exit_status),
            opt(self.signal),
            detail
        )
    }
    pub fn decode(s: &str) -> Option<Verdict> {
        let line = s.lines().next()?;
        let mut f = line.splitn(4, '\t');
        let class = f.next()?.to_string();
        let num = |x: Option<&str>| x.and_then(|v| v.parse::<i64>().ok());
        let exit_status = num(f.next());
        let signal = num(f.next());
        let detail = f.next().unwrap_or("").to_string();
        Some(Verdict {
            class,
            exit_status,
            signal,
            detail,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Outcome {
    pub verdict: Verdict,
    pub seed: u64,
    pub incarnations: u64,
    pub digest: String,
    pub traps: u64,
    pub switches: u64,
    pub refused: Vec<String>,
    pub wall_ms: u64,
    /// Blocking I/O counters: parks, re-attempts, spurious re-attempts, blocking calls
    /// completed, of which parked at least once.
    pub io: [u64; 5],
    /// One JSON object per crash.
    pub crashes: Vec<String>,
    /// JSON objects for the first injected faults, and the total.
    pub faults_injected: Vec<String>,
    pub faults_count: usize,
    /// Instruction channels.
    pub insn: InsnCounts,
    /// Network wire counters, `NET_NAMES` order, summed over incarnations
    /// (`peak_queued` and `sup_hwm_kb` are maxima).
    pub net: [u64; NET_FIELDS],
    /// `unix_sockets_in_flight` (the bucket-D label for in-flight descriptor cycles), summed
    /// over incarnations.
    pub unix_sockets: u64,
    /// Counter preemption: status ("" without `--pmu`, "on", "off: <reason>") and the
    /// counters, `proto::ctl::PMU_NAMES` order (summed; `max_skid` is a maximum).
    pub pmu: (String, [u64; proto::ctl::PMU_FIELDS]),
    pub sdk: SdkReport,
}

/// The SDK's site table and violation (`proto::sdk::SdkTab`), folded over incarnations.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SdkReport {
    /// Sorted by label, then kind.
    pub sites: Vec<SdkSite>,
    pub dropped: u64,
    pub setup_complete: bool,
    /// The failed `always`: (label, detail).
    pub violation: Option<(String, String)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SdkSite {
    pub kind: u8,
    pub label: String,
    pub location: String,
    pub evaluated: u64,
    pub held: u64,
    pub value: i64,
}

impl SdkReport {
    pub fn read(t: &proto::sdk::SdkTab) -> SdkReport {
        let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        let mut r = SdkReport {
            sites: t
                .used()
                .iter()
                .map(|x| SdkSite {
                    kind: x.kind,
                    label: s(x.label()),
                    location: s(x.loc()),
                    evaluated: x.evaluated,
                    held: x.held,
                    value: x.value,
                })
                .collect(),
            dropped: t.dropped,
            setup_complete: t.setup_seq != 0,
            violation: t.violation_parts().map(|(l, d)| (s(l), s(d))),
        };
        r.sites
            .sort_by(|a, b| (&a.label, a.kind).cmp(&(&b.label, b.kind)));
        r
    }
    /// Fold a later incarnation in: counts add, a knob keeps its last value.
    pub fn add(&mut self, b: SdkReport) {
        for x in b.sites {
            match self
                .sites
                .iter_mut()
                .find(|y| y.kind == x.kind && y.label == x.label)
            {
                Some(y) => {
                    y.evaluated += x.evaluated;
                    y.held += x.held;
                    if x.evaluated > 0 {
                        y.value = x.value;
                    }
                    if y.location.is_empty() {
                        y.location = x.location;
                    }
                }
                None => self.sites.push(x),
            }
        }
        self.sites
            .sort_by(|a, b| (&a.label, a.kind).cmp(&(&b.label, b.kind)));
        self.dropped += b.dropped;
        self.setup_complete |= b.setup_complete;
        if b.violation.is_some() {
            self.violation = b.violation;
        }
    }
    /// `{"sites":[{"kind","label","location","evaluated","held"[,"value"]}],"setup_complete",
    /// "violation":{"label","detail"}|null,"dropped"}`. `evaluated` counts reports (an SDK
    /// reports a passing assertion once per process image) or a point's evaluations; `held`
    /// counts reports whose condition held, hits of a `reachable`, firings of a point or delay.
    pub fn json(&self) -> String {
        let sites: Vec<String> = self
            .sites
            .iter()
            .map(|x| {
                let loc = if x.location.is_empty() {
                    "null".into()
                } else {
                    json_str(&x.location)
                };
                let value = if x.kind == proto::sdk::KIND_KNOB && x.evaluated > 0 {
                    format!(",\"value\":{}", x.value)
                } else {
                    String::new()
                };
                format!(
                    "{{\"kind\":{},\"label\":{},\"location\":{loc},\"evaluated\":{},\"held\":{}{value}}}",
                    json_str(proto::sdk::kind_name(x.kind)),
                    json_str(&x.label),
                    x.evaluated,
                    x.held
                )
            })
            .collect();
        let violation = match &self.violation {
            Some((l, d)) => format!("{{\"label\":{},\"detail\":{}}}", json_str(l), json_str(d)),
            None => "null".into(),
        };
        format!(
            "{{\"sites\":[{}],\"setup_complete\":{},\"violation\":{violation},\"dropped\":{}}}",
            sites.join(","),
            self.setup_complete,
            self.dropped
        )
    }
}

pub const NET_FIELDS: usize = 12;
pub const NET_NAMES: [&str; NET_FIELDS] = [
    "connections",
    "bytes",
    "chunks",
    "resets",
    "partitioned",
    "refused",
    "timeouts",
    "unknown_opts",
    "peak_queued",
    "sup_hwm_kb",
    "steps",
    "fins",
];

pub fn net_read(c: &proto::wire::NetCounters) -> [u64; NET_FIELDS] {
    use std::sync::atomic::Ordering::Relaxed;
    [
        c.connections.load(Relaxed),
        c.bytes.load(Relaxed),
        c.chunks.load(Relaxed),
        c.resets.load(Relaxed),
        c.partitioned.load(Relaxed),
        c.refused.load(Relaxed),
        c.timeouts.load(Relaxed),
        c.unknown_opts.load(Relaxed),
        c.peak_queued.load(Relaxed),
        c.sup_hwm_kb.load(Relaxed),
        c.steps.load(Relaxed),
        c.fins.load(Relaxed),
    ]
}

pub fn net_add(a: &mut [u64; NET_FIELDS], b: &[u64; NET_FIELDS]) {
    for (i, (x, y)) in a.iter_mut().zip(b).enumerate() {
        if NET_NAMES[i] == "peak_queued" || NET_NAMES[i] == "sup_hwm_kb" {
            *x = (*x).max(*y);
        } else {
            *x += y;
        }
    }
}

/// Instruction-channel counters, as in `proto::ctl::InsnCtl`, summed over incarnations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InsnCounts {
    /// By `proto::insn::SiteKind`: [unused, rdrand, rdseed, rdpid].
    pub patched: [u64; 4],
    /// By `proto::ctl::INSN_*`.
    pub emulated: [u64; 5],
    pub unscanned_exec_mappings: u64,
    pub rejected_sites: u64,
    pub rdpid_sites: u64,
    pub scanned_mappings: u64,
    pub scanned_bytes: u64,
    pub table_full: u64,
}

impl InsnCounts {
    pub fn read(c: &proto::ctl::InsnCtl) -> InsnCounts {
        use std::sync::atomic::Ordering::Relaxed;
        let mut o = InsnCounts::default();
        for (a, b) in o.patched.iter_mut().zip(&c.patched) {
            *a = b.load(Relaxed);
        }
        for (a, b) in o.emulated.iter_mut().zip(&c.emulated) {
            *a = b.load(Relaxed);
        }
        o.unscanned_exec_mappings = c.unscanned_exec_mappings.load(Relaxed);
        o.rejected_sites = c.rejected_sites.load(Relaxed);
        o.rdpid_sites = c.rdpid_sites.load(Relaxed);
        o.scanned_mappings = c.scanned_mappings.load(Relaxed);
        o.scanned_bytes = c.scanned_bytes.load(Relaxed);
        o.table_full = c.table_full.load(Relaxed);
        o
    }
    pub fn add(&mut self, b: &InsnCounts) {
        for (x, y) in self.patched.iter_mut().zip(b.patched) {
            *x += y;
        }
        for (x, y) in self.emulated.iter_mut().zip(b.emulated) {
            *x += y;
        }
        self.unscanned_exec_mappings += b.unscanned_exec_mappings;
        self.rejected_sites += b.rejected_sites;
        self.rdpid_sites += b.rdpid_sites;
        self.scanned_mappings += b.scanned_mappings;
        self.scanned_bytes += b.scanned_bytes;
        self.table_full += b.table_full;
    }
    /// The outcome fields: `"patched_sites":{..},"emulated":{..},"unscanned_exec_mappings":N,"insn_scan":{..}`.
    pub fn json(&self) -> String {
        let em: Vec<String> = proto::ctl::INSN_NAMES
            .iter()
            .zip(self.emulated)
            .map(|(n, v)| format!("\"{n}\":{v}"))
            .collect();
        format!(
            "\"patched_sites\":{{\"rdrand\":{},\"rdseed\":{}}},\"emulated\":{{{}}},\"unscanned_exec_mappings\":{},\
             \"insn_scan\":{{\"mappings\":{},\"bytes\":{},\"rejected_sites\":{},\"rdpid_sites\":{},\"table_full\":{}}}",
            self.patched[1],
            self.patched[2],
            em.join(","),
            self.unscanned_exec_mappings,
            self.scanned_mappings,
            self.scanned_bytes,
            self.rejected_sites,
            self.rdpid_sites,
            self.table_full
        )
    }
}

pub fn json_str(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(o, "\\u{:04x}", c as u32);
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

impl Outcome {
    pub fn to_json(&self) -> String {
        let opt = |v: Option<i64>| v.map(|x| x.to_string()).unwrap_or_else(|| "null".into());
        let refused: Vec<String> = self.refused.iter().map(|r| json_str(r)).collect();
        let mut s = format!(
            "{{\"class\":{},\"detail\":{},\"exit_status\":{},\"signal\":{},\"seed\":{},\"incarnations\":{},\"crashes\":[{}],\
             \"digest\":{},\"traps\":{},\"switches\":{},\"faults_injected\":[{}],\"faults_count\":{},\"refused\":[{}],{},\"wall_ms\":{},\
             \"io\":{{\"parks\":{},\"reattempts\":{},\"spurious\":{},\"blocking_done\":{},\"blocking_parked\":{}}},\"net\":{{{}}},\
             \"unix_sockets_in_flight\":{},\"sdk\":{}}}\n",
            json_str(&self.verdict.class),
            json_str(&self.verdict.detail),
            opt(self.verdict.exit_status),
            opt(self.verdict.signal),
            self.seed,
            self.incarnations,
            self.crashes.join(","),
            json_str(&self.digest),
            self.traps,
            self.switches,
            self.faults_injected.join(","),
            self.faults_count,
            refused.join(","),
            self.insn.json(),
            self.wall_ms,
            self.io[0],
            self.io[1],
            self.io[2],
            self.io[3],
            self.io[4],
            NET_NAMES.iter().zip(self.net).map(|(n, v)| format!("\"{n}\":{v}")).collect::<Vec<_>>().join(","),
            self.unix_sockets,
            self.sdk.json()
        );
        if !self.pmu.0.is_empty() {
            // Only with --pmu: the default outcome is unchanged.
            s.truncate(s.len() - 2);
            let st: Vec<String> = proto::ctl::PMU_NAMES
                .iter()
                .zip(self.pmu.1)
                .map(|(n, v)| format!("\"{n}\":{v}"))
                .collect();
            s.push_str(&format!(
                ",\"pmu\":{},\"pmu_stats\":{{{}}}}}\n",
                json_str(&self.pmu.0),
                st.join(",")
            ));
        }
        s
    }
}
