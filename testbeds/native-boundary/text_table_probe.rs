//! A constant table stored in .text after a function's `.size`, under a local
//! label, as s2n-bignum's curve tables are. Decoded as code, its first bytes
//! are a far return (`cb`) and an opcode invalid in 64-bit mode (`06`). The
//! function reads the table's second word, 42.

std::arch::global_asm!(
    ".pushsection .text.table_probe,\"ax\",@progbits",
    ".globl table_probe",
    ".type table_probe,@function",
    "table_probe:",
    "lea rax, [rip + Ltable_probe_data]",
    "mov rax, qword ptr [rax + 8]",
    "ret",
    ".size table_probe, .-table_probe",
    "Ltable_probe_data:",
    ".quad 0x06cb",
    ".quad 42",
    ".popsection",
);

unsafe extern "C" {
    fn table_probe() -> u64;
}

fn main() {
    println!("TABLE_PROBE value={}", unsafe { table_probe() });
}
