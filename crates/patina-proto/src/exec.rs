//! What `execve` runs: the kernel's `#!` line (`fs/binfmt_script.c`) and the reasons an image
//! is not run. Shared by the runtime, which resolves every image (the first one and each
//! `execve`), and the supervisor, which words a first image that cannot run.

/// Bytes of a file the kernel reads to choose how to run it (`BINPRM_BUF_SIZE`).
pub const BINPRM_BUF_SIZE: usize = 256;
/// Nested `#!` interpreters the kernel follows (`exec_binprm`); one more is `ELOOP`.
pub const MAX_DEPTH: usize = 5;

/// A `#!` line: the interpreter as written and its optional argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Script<'a> {
    pub interp: &'a [u8],
    pub arg: Option<&'a [u8]>,
}

/// Why a file's first bytes are not a usable `#!` line. Every one is `ENOEXEC`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotScript {
    /// It does not start with `#!`.
    NoMark,
    /// The line names no interpreter.
    NoInterp,
    /// The interpreter's name does not end within the first 255 bytes.
    Truncated,
}

/// Parse the first bytes of a file (`head`, as read: at most `BINPRM_BUF_SIZE`) as the kernel's
/// `load_script` does: the line ends at the first newline within `BINPRM_BUF_SIZE` bytes, or at
/// byte 255; spaces and tabs around it are dropped; the interpreter ends at a space, tab or
/// NUL; what follows, up to the line's end or a NUL, is one argument. A carriage return is
/// neither, so a CRLF line's interpreter (or argument) ends in `\r`.
pub fn parse(head: &[u8]) -> Result<Script<'_>, NotScript> {
    let n = head.len().min(BINPRM_BUF_SIZE);
    let at = |i: usize| if i < n { head[i] } else { 0 };
    let spacetab = |c: u8| c == b' ' || c == b'\t';
    let term = |c: u8| spacetab(c) || c == 0;
    if at(0) != b'#' || at(1) != b'!' {
        return Err(NotScript::NoMark);
    }
    // The kernel's ranges are inclusive of their last byte.
    let buf_end = BINPRM_BUF_SIZE - 1;
    let mut i_end = match (0..BINPRM_BUF_SIZE).find(|&i| at(i) == b'\n') {
        Some(i) => i,
        None => {
            let Some(s) = (2..=buf_end).find(|&i| !spacetab(at(i))) else {
                return Err(NotScript::NoInterp);
            };
            if !(s..=buf_end).any(|i| term(at(i))) {
                return Err(NotScript::Truncated);
            }
            buf_end
        }
    };
    while spacetab(at(i_end - 1)) {
        i_end -= 1;
    }
    let i_name = match (2..=i_end).find(|&i| !spacetab(at(i))) {
        Some(i) if i != i_end => i,
        _ => return Err(NotScript::NoInterp),
    };
    let i_sep = (i_name..=i_end).find(|&i| term(at(i)));
    let i_arg = i_sep
        .filter(|&s| at(s) != 0)
        .and_then(|s| (s..=i_end).find(|&i| !spacetab(at(i))));
    // The kernel writes a NUL at the line's end, and at the separator when there is an
    // argument; each string runs to the first NUL.
    let cstr_end = |from: usize, stop: usize| (from..stop).find(|&i| at(i) == 0).unwrap_or(stop);
    let interp_stop = match i_arg {
        Some(_) => i_sep.unwrap_or(i_end),
        None => i_end,
    };
    let interp = &head[i_name..cstr_end(i_name, interp_stop).min(n)];
    let arg = i_arg.map(|a| &head[a.min(n)..cstr_end(a, i_end).min(n)]);
    Ok(Script { interp, arg })
}

/// Why an image is not run, beyond its errno: what the supervisor says when the first image
/// cannot run (`ctl::HE_EXEC`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Why {
    /// Only the errno says.
    Errno = 0,
    NotRegular,
    NotExecutable,
    Unreadable,
    Empty,
    /// Neither an ELF image nor `#!`.
    NoMark,
    NoInterp,
    Truncated,
    /// The interpreter's name ends in a carriage return (a CRLF file).
    CarriageReturn,
    TooDeep,
    NameTooLong,
    Elf32,
    ElfMachine,
    ElfType,
    ElfShort,
    /// More program headers than the loader takes, or of another size.
    ElfHeaders,
    ElfNoLoad,
    /// The ELF interpreter (`PT_INTERP`) is missing.
    ElfInterp,
    Hidden,
    /// The ELF interpreter is not an image the runtime loads.
    ElfInterpBad,
}

impl Why {
    pub fn from_code(c: u64) -> Why {
        use Why::*;
        const ALL: [Why; 20] = [
            Errno,
            NotRegular,
            NotExecutable,
            Unreadable,
            Empty,
            NoMark,
            NoInterp,
            Truncated,
            CarriageReturn,
            TooDeep,
            NameTooLong,
            Elf32,
            ElfMachine,
            ElfType,
            ElfShort,
            ElfHeaders,
            ElfNoLoad,
            ElfInterp,
            Hidden,
            ElfInterpBad,
        ];
        ALL.iter()
            .copied()
            .find(|w| *w as u64 == c)
            .unwrap_or(Errno)
    }

    pub fn from_not_script(n: NotScript) -> Why {
        match n {
            NotScript::NoMark => Why::NoMark,
            NotScript::NoInterp => Why::NoInterp,
            NotScript::Truncated => Why::Truncated,
        }
    }

    /// The reason in words, for "cannot run FILE: ...".
    pub fn text(self) -> &'static str {
        match self {
            Why::Errno => "",
            Why::NotRegular => "not a regular file",
            Why::NotExecutable => "no execute permission",
            Why::Unreadable => "not readable (the runtime loads the image itself)",
            Why::Empty => "an empty file",
            Why::NoMark => {
                "neither an ELF image nor a script starting with #! (a shell runs such a file as a script; name the shell: sh FILE)"
            }
            Why::NoInterp => "its #! line names no interpreter",
            Why::Truncated => "its #! interpreter's name does not end within the first 255 bytes",
            Why::CarriageReturn => "its #! line ends in a carriage return (CRLF line endings)",
            Why::TooDeep => "more than 5 nested #! interpreters",
            Why::NameTooLong => "a #! interpreter or argument too long",
            Why::Elf32 => "a 32-bit ELF image (only 64-bit images of this architecture run)",
            Why::ElfMachine => "an ELF image for another architecture",
            Why::ElfType => "an ELF image that is neither an executable nor a shared object",
            Why::ElfShort => "a truncated ELF image",
            Why::ElfHeaders => "an ELF image with more than 64 program headers, or of another size",
            Why::ElfNoLoad => "an ELF image with no loadable segment",
            Why::ElfInterp => "its ELF interpreter (PT_INTERP) is not in the sandbox",
            Why::Hidden => "a path Patina keeps from the program",
            Why::ElfInterpBad => {
                "its ELF interpreter (PT_INTERP) is not a 64-bit ELF image of this architecture"
            }
        }
    }
}

/// Whether the ELF header (`head`, the file's first bytes) is one the runtime loads, and why
/// not. The program headers are checked by the caller, which reads them.
pub fn elf_header(head: &[u8]) -> Result<(), Why> {
    if head.len() < 64 {
        return Err(Why::ElfShort);
    }
    if head[4] != 2 {
        return Err(Why::Elf32);
    }
    if u16::from_le_bytes([head[18], head[19]]) != crate::abi::ELF_MACHINE {
        return Err(Why::ElfMachine);
    }
    let typ = u16::from_le_bytes([head[16], head[17]]);
    if typ != 2 && typ != 3 {
        return Err(Why::ElfType);
    }
    let phentsize = u16::from_le_bytes([head[54], head[55]]);
    let phnum = u16::from_le_bytes([head[56], head[57]]);
    if phentsize != 56 || phnum > 64 {
        return Err(Why::ElfHeaders);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(h: &[u8]) -> (&[u8], Option<&[u8]>) {
        let s = parse(h).unwrap();
        (s.interp, s.arg)
    }

    #[test]
    fn lines_as_the_kernel_reads_them() {
        assert_eq!(ok(b"#!/bin/sh\necho"), (&b"/bin/sh"[..], None));
        assert_eq!(ok(b"#! \t/bin/sh \t\n"), (&b"/bin/sh"[..], None));
        assert_eq!(
            ok(b"#!/usr/bin/env  python3 -u \n"),
            (&b"/usr/bin/env"[..], Some(&b"python3 -u"[..]))
        );
        // No newline: the line is the file (the rest of the buffer is zeros).
        assert_eq!(ok(b"#!/bin/sh"), (&b"/bin/sh"[..], None));
        // CRLF: the carriage return stays.
        assert_eq!(ok(b"#!/bin/sh\r\n"), (&b"/bin/sh\r"[..], None));
        assert_eq!(
            ok(b"#!/bin/sh -e\r\n"),
            (&b"/bin/sh"[..], Some(&b"-e\r"[..]))
        );
        // A NUL ends the interpreter (no argument) or the argument.
        assert_eq!(ok(b"#!/bin/sh\0 -x\n"), (&b"/bin/sh"[..], None));
        assert_eq!(
            ok(b"#!/bin/sh -a\0b\n"),
            (&b"/bin/sh"[..], Some(&b"-a"[..]))
        );
    }

    #[test]
    fn not_scripts() {
        assert_eq!(parse(b""), Err(NotScript::NoMark));
        assert_eq!(parse(b"#"), Err(NotScript::NoMark));
        assert_eq!(parse(b"echo hi\n"), Err(NotScript::NoMark));
        assert_eq!(parse(b"#!\n"), Err(NotScript::NoInterp));
        assert_eq!(parse(b"#!  \t \n"), Err(NotScript::NoInterp));
        // Without a newline the zeros after the file end are the line: an empty name (the
        // kernel then opens "", the working directory: EACCES).
        assert_eq!(ok(b"#!"), (&b""[..], None));
        assert_eq!(ok(b"#!   "), (&b""[..], None));
    }

    #[test]
    fn the_255_byte_line() {
        let mut long = [b'a'; BINPRM_BUF_SIZE];
        long[0] = b'#';
        long[1] = b'!';
        long[2] = b'/';
        // An interpreter name filling the buffer, no newline: truncated, ENOEXEC.
        assert_eq!(parse(&long), Err(NotScript::Truncated));
        // A newline at byte 255 still ends the line within the buffer.
        long[255] = b'\n';
        assert_eq!(parse(&long).unwrap().interp.len(), 253);
        // A name that ends, an argument cut at byte 255.
        long[255] = b'b';
        long[10] = b' ';
        let s = parse(&long).unwrap();
        assert_eq!((s.interp.len(), s.arg.unwrap().len()), (8, 255 - 11));
        // A newline beyond the buffer is not seen.
        let mut longer = [b'x'; 300];
        longer[..12].copy_from_slice(b"#!/bin/sh -a");
        longer[299] = b'\n';
        let s = parse(&longer).unwrap();
        assert_eq!(s.arg.unwrap().len(), 255 - 10);
    }

    #[test]
    fn why_codes_round_trip() {
        for c in 0..32 {
            let w = Why::from_code(c);
            assert!(w as u64 == c || w == Why::Errno);
        }
        assert_eq!(Why::from_code(Why::Hidden as u64), Why::Hidden);
    }
}
