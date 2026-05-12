//! ML Guard native engine (Rust + PyO3).
//!
//! This crate compiles to the Python extension `ml_guard_engine`.
//! The Python side (`ml_guard.scanners.pickle_scanner`) attempts to import
//! it and uses it when available; otherwise it falls back to pure Python
//! (`pickletools.genops`). Correctness is identical — only speed differs
//! on large files.
//!
//! Local build:
//!     pip install maturin
//!     cd rust_engine && maturin develop --release
//!
//! Building distributable wheels:
//!     maturin build --release --strip
//!
//! IMPORTANT: the set of detected RCE callables, severities, and rule_ids MUST
//! match `ml_guard/scanners/pickle_scanner.py`. If you change it there,
//! change it here too — otherwise scanner output depends on whether the
//! user has the native module. The long-term fix is to extract the rule list
//! into a shared JSON and read it from both sides; that's a TODO.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::collections::HashSet;

// ---------- Knowledge base (mirrors Python) ----------

const RCE_CALLABLES: &[(&str, &str)] = &[
    ("os", "system"), ("os", "popen"),
    ("os", "execv"), ("os", "execve"), ("os", "execvp"), ("os", "execvpe"),
    ("os", "spawnl"), ("os", "spawnv"),
    ("posix", "system"), ("nt", "system"),
    ("subprocess", "Popen"), ("subprocess", "call"), ("subprocess", "run"),
    ("subprocess", "check_call"), ("subprocess", "check_output"),
    ("subprocess", "getoutput"), ("subprocess", "getstatusoutput"),
    ("commands", "getoutput"),
    ("builtins", "eval"), ("builtins", "exec"),
    ("builtins", "compile"), ("builtins", "__import__"),
    ("__builtin__", "eval"), ("__builtin__", "exec"),
    ("__builtin__", "compile"), ("__builtin__", "__import__"),
    ("importlib", "import_module"),
    ("runpy", "run_path"), ("runpy", "_run_code"),
    ("pty", "spawn"), ("platform", "popen"),
    ("ctypes", "CDLL"), ("ctypes", "WinDLL"),
    ("ctypes", "OleDLL"), ("ctypes", "PyDLL"),
];

const SUSPICIOUS_MODULES: &[&str] = &[
    "socket", "urllib", "urllib2", "urllib.request",
    "http", "http.client", "httplib",
    "requests", "ftplib", "telnetlib", "smtplib",
    "shutil", "tempfile", "webbrowser",
    "marshal", "code", "codeop",
    "pickle", "pickletools", "_pickle",
];

const BENIGN_TOP_MODULES: &[&str] = &[
    "torch", "numpy", "collections", "_codecs",
];

// ---------- Pickle parser ----------

#[derive(Debug, Clone)]
struct RawFinding {
    rule_id: String,
    severity: String,
    message: String,
    location: String,
    snippet: String,
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self { Self { data, pos: 0 } }
    fn remaining(&self) -> usize { self.data.len().saturating_sub(self.pos) }
    fn read_byte(&mut self) -> Option<u8> {
        if self.pos >= self.data.len() { return None; }
        let b = self.data[self.pos]; self.pos += 1; Some(b)
    }
    fn read_n(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n { return None; }
        let s = &self.data[self.pos..self.pos + n]; self.pos += n; Some(s)
    }
    fn read_line(&mut self) -> Option<&'a [u8]> {
        let start = self.pos;
        while self.pos < self.data.len() && self.data[self.pos] != b'\n' {
            self.pos += 1;
        }
        if self.pos >= self.data.len() { return None; }
        let line = &self.data[start..self.pos];
        self.pos += 1;
        Some(line)
    }
    fn read_u8(&mut self) -> Option<usize> { self.read_byte().map(|b| b as usize) }
    fn read_u16_le(&mut self) -> Option<usize> {
        let b = self.read_n(2)?; Some(u16::from_le_bytes([b[0], b[1]]) as usize)
    }
    fn read_u32_le(&mut self) -> Option<usize> {
        let b = self.read_n(4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
    }
    fn read_u64_le(&mut self) -> Option<usize> {
        let b = self.read_n(8)?;
        Some(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]) as usize)
    }
}

#[derive(Clone, Debug)]
enum StackVal {
    Str(String),
    Other,
}

fn analyze_pickle(data: &[u8]) -> Vec<RawFinding> {
    let mut findings = Vec::new();
    let mut cur = Cursor::new(data);
    let mut stack: Vec<StackVal> = Vec::with_capacity(64);
    let mut reported: HashSet<(String, String)> = HashSet::new();

    const MAX_OPS: usize = 5_000_000;
    let mut ops = 0usize;

    loop {
        if ops >= MAX_OPS {
            findings.push(RawFinding {
                rule_id: "pickle-too-many-opcodes".into(),
                severity: "low".into(),
                message: format!("Stopped after {} opcodes (DoS guard)", MAX_OPS),
                location: format!("offset 0x{:x}", cur.pos),
                snippet: String::new(),
            });
            break;
        }
        ops += 1;

        let op_pos = cur.pos;
        let op = match cur.read_byte() {
            Some(b) => b,
            None => break,
        };

        match op {
            b'.' => break,                                 // STOP
            0x80 => { let _ = cur.read_byte(); }           // PROTO
            0x95 => { let _ = cur.read_n(8); }             // FRAME

            // structural / numeric — push Other and consume the payload
            b'(' | b'N' | 0x88 | 0x89
            | b'}' | b']' | 0x8f | b')'
            | 0x85 | 0x86 | 0x87 | b't'
            | b'l' | b'd' => {
                stack.push(StackVal::Other);
            }
            b'K' => { let _ = cur.read_byte(); stack.push(StackVal::Other); }
            b'M' => { let _ = cur.read_n(2); stack.push(StackVal::Other); }
            b'J' => { let _ = cur.read_n(4); stack.push(StackVal::Other); }
            b'G' => { let _ = cur.read_n(8); stack.push(StackVal::Other); }
            b'L' | b'F' => { let _ = cur.read_line(); stack.push(StackVal::Other); }
            0x8a => {
                let n = cur.read_u8().unwrap_or(0);
                let _ = cur.read_n(n); stack.push(StackVal::Other);
            }
            0x8b => {
                let n = cur.read_u32_le().unwrap_or(0);
                let _ = cur.read_n(n); stack.push(StackVal::Other);
            }

            // strings and byte blocks
            0x8c /* SHORT_BINUNICODE */ => {
                let n = cur.read_u8().unwrap_or(0);
                let bytes = cur.read_n(n).unwrap_or(&[]);
                stack.push(StackVal::Str(String::from_utf8_lossy(bytes).into_owned()));
            }
            0x8d /* BINUNICODE */ => {
                let n = cur.read_u32_le().unwrap_or(0);
                let bytes = cur.read_n(n).unwrap_or(&[]);
                stack.push(StackVal::Str(String::from_utf8_lossy(bytes).into_owned()));
            }
            0x8e /* BINUNICODE8 */ => {
                let n = cur.read_u64_le().unwrap_or(0);
                let bytes = cur.read_n(n).unwrap_or(&[]);
                stack.push(StackVal::Str(String::from_utf8_lossy(bytes).into_owned()));
            }
            b'U' /* SHORT_BINSTRING */ => {
                let n = cur.read_u8().unwrap_or(0);
                let bytes = cur.read_n(n).unwrap_or(&[]);
                stack.push(StackVal::Str(String::from_utf8_lossy(bytes).into_owned()));
            }
            b'T' /* BINSTRING */ => {
                let n = cur.read_u32_le().unwrap_or(0);
                let bytes = cur.read_n(n).unwrap_or(&[]);
                stack.push(StackVal::Str(String::from_utf8_lossy(bytes).into_owned()));
            }
            b'C' /* SHORT_BINBYTES */ => {
                let n = cur.read_u8().unwrap_or(0);
                let bytes = cur.read_n(n).unwrap_or(&[]);
                stack.push(StackVal::Str(String::from_utf8_lossy(bytes).into_owned()));
            }
            b'B' /* BINBYTES */ => {
                let n = cur.read_u32_le().unwrap_or(0);
                let bytes = cur.read_n(n).unwrap_or(&[]);
                stack.push(StackVal::Str(String::from_utf8_lossy(bytes).into_owned()));
            }
            b'S' | b'V' /* STRING / UNICODE */ => {
                let line = cur.read_line().unwrap_or(&[]);
                stack.push(StackVal::Str(String::from_utf8_lossy(line).into_owned()));
            }

            // GLOBAL "module\nqualname\n"
            b'c' => {
                let module_b = cur.read_line().unwrap_or(&[]);
                let qualname_b = cur.read_line().unwrap_or(&[]);
                let module = String::from_utf8_lossy(module_b).into_owned();
                let qualname = String::from_utf8_lossy(qualname_b).into_owned();
                on_global(&module, &qualname, op_pos, &mut findings, &mut reported);
                stack.push(StackVal::Other);
            }
            // STACK_GLOBAL — top two stack entries
            0x93 => {
                if stack.len() >= 2 {
                    let qualname = stack.pop().unwrap();
                    let module = stack.pop().unwrap();
                    if let (StackVal::Str(m), StackVal::Str(q)) = (&module, &qualname) {
                        on_global(m, q, op_pos, &mut findings, &mut reported);
                    } else {
                        findings.push(RawFinding {
                            rule_id: "pickle-stack-global-opaque".into(),
                            severity: "medium".into(),
                            message: "STACK_GLOBAL with non-string operands (possibly obfuscated)".into(),
                            location: format!("offset 0x{:x}", op_pos),
                            snippet: String::new(),
                        });
                    }
                } else {
                    findings.push(RawFinding {
                        rule_id: "pickle-stack-global-opaque".into(),
                        severity: "medium".into(),
                        message: "STACK_GLOBAL on empty stack (malformed pickle)".into(),
                        location: format!("offset 0x{:x}", op_pos),
                        snippet: String::new(),
                    });
                }
                stack.push(StackVal::Other);
            }
            // REDUCE — pop 2, push 1
            b'R' => { stack.pop(); stack.pop(); stack.push(StackVal::Other); }
            // POP / POP_MARK
            b'0' => { stack.pop(); }
            b'1' => {}

            // INST/OBJ — deprecated
            b'i' => {
                let _ = cur.read_line();
                let _ = cur.read_line();
                findings.push(RawFinding {
                    rule_id: "pickle-deprecated-opcode".into(),
                    severity: "low".into(),
                    message: "Deprecated INST opcode".into(),
                    location: format!("offset 0x{:x}", op_pos),
                    snippet: String::new(),
                });
                stack.push(StackVal::Other);
            }
            b'o' => {
                findings.push(RawFinding {
                    rule_id: "pickle-deprecated-opcode".into(),
                    severity: "low".into(),
                    message: "Deprecated OBJ opcode".into(),
                    location: format!("offset 0x{:x}", op_pos),
                    snippet: String::new(),
                });
                stack.push(StackVal::Other);
            }

            // PUT/GET and memo — payload only, stack unchanged
            b'p' | b'g' => { let _ = cur.read_line(); }
            b'q' | b'h' => { let _ = cur.read_byte(); }
            b'r' | b'j' => { let _ = cur.read_n(4); }
            0x94 /* MEMOIZE */ => {}

            // BUILD/APPEND/APPENDS/SETITEM/SETITEMS — stack-stable for our tracking
            b'b' | b'a' | b'e' | b's' | b'u' => {}

            _ => {}
        }
    }

    findings
}

fn on_global(
    module: &str,
    qualname: &str,
    pos: usize,
    findings: &mut Vec<RawFinding>,
    reported: &mut HashSet<(String, String)>,
) {
    let key = (module.to_string(), qualname.to_string());
    if reported.contains(&key) { return; }

    if RCE_CALLABLES.iter().any(|(m, q)| *m == module && *q == qualname) {
        reported.insert(key.clone());
        findings.push(RawFinding {
            rule_id: "pickle-dangerous-global".into(),
            severity: "critical".into(),
            message: format!("Dangerous global imported: {}.{} (known RCE primitive)", module, qualname),
            location: format!("offset 0x{:x}", pos),
            snippet: format!("{}.{}", module, qualname),
        });
        return;
    }

    let top = module.split('.').next().unwrap_or(module);
    if SUSPICIOUS_MODULES.iter().any(|m| *m == module || *m == top) {
        reported.insert(key);
        findings.push(RawFinding {
            rule_id: "pickle-suspicious-module".into(),
            severity: "high".into(),
            message: format!("Suspicious module imported: {}.{} (not expected in ML weights)", module, qualname),
            location: format!("offset 0x{:x}", pos),
            snippet: format!("{}.{}", module, qualname),
        });
        return;
    }

    if !BENIGN_TOP_MODULES.iter().any(|m| *m == top) {
        reported.insert(key);
        findings.push(RawFinding {
            rule_id: "pickle-unusual-module".into(),
            severity: "medium".into(),
            message: format!("Unusual module for ML weights: {}.{}", module, qualname),
            location: format!("offset 0x{:x}", pos),
            snippet: format!("{}.{}", module, qualname),
        });
    }
}

// ---------- PyO3 interface ----------

/// Scan pickle stream bytes and return list[dict] findings.
#[pyfunction]
fn scan_pickle_bytes<'py>(py: Python<'py>, data: &[u8]) -> PyResult<&'py PyList> {
    let raw = analyze_pickle(data);
    let out = PyList::empty(py);
    for f in raw {
        let d = PyDict::new(py);
        d.set_item("rule_id", f.rule_id)?;
        d.set_item("severity", f.severity)?;
        d.set_item("message", f.message)?;
        d.set_item("location", f.location)?;
        d.set_item("snippet", f.snippet)?;
        out.append(d)?;
    }
    Ok(out)
}

/// Engine version.
#[pyfunction]
fn engine_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[pymodule]
fn ml_guard_engine(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scan_pickle_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(engine_version, m)?)?;
    Ok(())
}

// ---------- Rust unit tests ----------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_no_panic() {
        assert!(analyze_pickle(&[]).is_empty());
    }

    #[test]
    fn proto_marker_only() {
        let data = [0x80, 0x04, b'N', b'.'];
        assert!(analyze_pickle(&data).is_empty());
    }

    #[test]
    fn detects_os_system_via_global() {
        let mut data = vec![0x80, 0x04, b'c'];
        data.extend_from_slice(b"os\nsystem\n");
        data.push(b'.');
        let f = analyze_pickle(&data);
        assert!(f.iter().any(|r|
            r.rule_id == "pickle-dangerous-global" && r.snippet.contains("os.system")
        ));
    }

    #[test]
    fn detects_via_stack_global() {
        let mut data = vec![0x80, 0x04];
        data.extend_from_slice(&[0x8c, 8]); data.extend_from_slice(b"builtins");
        data.extend_from_slice(&[0x8c, 4]); data.extend_from_slice(b"eval");
        data.push(0x93); data.push(b'.');
        let f = analyze_pickle(&data);
        assert!(f.iter().any(|r|
            r.rule_id == "pickle-dangerous-global" && r.snippet.contains("builtins.eval")
        ), "got: {:?}", f);
    }

    #[test]
    fn unusual_module_emits_medium() {
        let mut data = vec![0x80, 0x04, b'c'];
        data.extend_from_slice(b"weirdpkg\nthing\n");
        data.push(b'.');
        let f = analyze_pickle(&data);
        assert!(f.iter().any(|r| r.rule_id == "pickle-unusual-module"));
    }
}
