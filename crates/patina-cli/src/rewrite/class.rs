//! The site classes, the same on every architecture (`result.json` counts them by name).

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Class {
    BackBranch,
    BackCall,
    IndirectJump,
    Atomic,
}

impl Class {
    pub const ALL: [Class; 4] = [
        Class::BackBranch,
        Class::BackCall,
        Class::IndirectJump,
        Class::Atomic,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Class::BackBranch => "back-branch",
            Class::BackCall => "back-call",
            Class::IndirectJump => "indirect-jump",
            Class::Atomic => "atomic",
        }
    }
}
