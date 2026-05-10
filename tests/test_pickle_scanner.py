"""Тесты pickle scanner.

Проверяем, что:
  • Безобидный pickle не даёт CRITICAL/HIGH (только возможные MEDIUM на не-ML модули).
  • Каждый известный RCE-вектор детектируется как CRITICAL.
  • PyTorch ZIP-формат разворачивается и сканируется.
  • Битый pickle не роняет сканер — даёт MEDIUM с parse-error.
"""
from __future__ import annotations

from pathlib import Path

from ml_guard.findings import Severity
from ml_guard.scanners.pickle_scanner import PickleScanner


def _critical_count(findings) -> int:
    return sum(1 for f in findings if f.severity == Severity.CRITICAL)


def _has_rule(findings, rule_id: str) -> bool:
    return any(f.rule_id == rule_id for f in findings)


def test_can_scan_extensions(tmp_workspace: Path):
    s = PickleScanner()
    for ext in (".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt"):
        f = tmp_workspace / f"x{ext}"
        f.write_bytes(b"\x80\x04N.")
        assert s.can_scan(f), f"should accept {ext}"

    # текстовый файл — не должен браться
    txt = tmp_workspace / "x.txt"
    txt.write_text("hello")
    assert not s.can_scan(txt)


def test_benign_pickle_is_clean(benign_pickle_path: Path):
    s = PickleScanner()
    findings = s.scan(benign_pickle_path)
    # Никаких critical в безобидном pickle быть не должно.
    assert _critical_count(findings) == 0, [f.to_dict() for f in findings]


def test_detects_os_system(malicious_os_pickle_path: Path):
    s = PickleScanner()
    findings = s.scan(malicious_os_pickle_path)
    assert _critical_count(findings) >= 1
    assert _has_rule(findings, "pickle-dangerous-global")
    # На Linux os.system → posix.system, на Windows → nt.system при сериализации.
    assert any(
        ("os.system" in f.snippet or "posix.system" in f.snippet or "nt.system" in f.snippet)
        for f in findings
    )


def test_detects_eval(malicious_eval_pickle_path: Path):
    s = PickleScanner()
    findings = s.scan(malicious_eval_pickle_path)
    assert _critical_count(findings) >= 1
    assert _has_rule(findings, "pickle-dangerous-global")
    assert any("eval" in f.snippet for f in findings)


def test_detects_subprocess(malicious_subprocess_pickle_path: Path):
    s = PickleScanner()
    findings = s.scan(malicious_subprocess_pickle_path)
    assert _critical_count(findings) >= 1
    assert any("subprocess" in f.message.lower() for f in findings)


def test_torch_zip_format(torch_zip_with_malicious_pickle: Path):
    s = PickleScanner()
    findings = s.scan(torch_zip_with_malicious_pickle)
    # Внутри ZIP лежит вредоносный pickle — должны его найти.
    assert _critical_count(findings) >= 1, [f.to_dict() for f in findings]
    # location должна содержать имя члена ZIP-архива
    assert any("data.pkl" in f.location for f in findings if f.severity == Severity.CRITICAL)


def test_corrupt_pickle_does_not_crash(corrupt_pickle_path: Path):
    s = PickleScanner()
    findings = s.scan(corrupt_pickle_path)
    # Должен быть finding о parse-error, но не исключение.
    assert _has_rule(findings, "pickle-parse-error")


def test_findings_have_filled_fields(malicious_os_pickle_path: Path):
    """Sanity: rule_id, severity, message — не пустые."""
    s = PickleScanner()
    findings = s.scan(malicious_os_pickle_path)
    for f in findings:
        assert f.rule_id
        assert f.severity in Severity
        assert f.message
