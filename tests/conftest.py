"""Общие фикстуры для тестов ML Guard."""
from __future__ import annotations

import io
import pickle
import struct
import zipfile
from pathlib import Path

import pytest


@pytest.fixture
def tmp_workspace(tmp_path: Path) -> Path:
    """Свежая временная директория для каждого теста."""
    return tmp_path


# --- pickle-фабрики ---------------------------------------------------------

class _MaliciousOsSystem:
    """Объект, при анмаршалинге которого сработает os.system('echo pwned').

    ВНИМАНИЕ: мы НИКОГДА не делаем pickle.loads() на результат.
    Мы только pickle.dumps()'им и проверяем, что сканер ловит это статически.
    """
    def __reduce__(self):
        import os
        return (os.system, ("echo pwned",))


class _MaliciousEval:
    def __reduce__(self):
        import builtins
        return (builtins.eval, ("__import__('os').system('id')",))


class _MaliciousSubprocess:
    def __reduce__(self):
        import subprocess
        return (subprocess.Popen, (["sh", "-c", "id"],))


@pytest.fixture
def benign_pickle_path(tmp_path: Path) -> Path:
    """Безобидный pickle (dict со строками и числами)."""
    p = tmp_path / "benign.pkl"
    with p.open("wb") as f:
        pickle.dump({"weights": [1.0, 2.0, 3.0], "name": "model"}, f)
    return p


@pytest.fixture
def malicious_os_pickle_path(tmp_path: Path) -> Path:
    p = tmp_path / "malicious_os.pkl"
    with p.open("wb") as f:
        pickle.dump(_MaliciousOsSystem(), f)
    return p


@pytest.fixture
def malicious_eval_pickle_path(tmp_path: Path) -> Path:
    p = tmp_path / "malicious_eval.pkl"
    with p.open("wb") as f:
        pickle.dump(_MaliciousEval(), f)
    return p


@pytest.fixture
def malicious_subprocess_pickle_path(tmp_path: Path) -> Path:
    p = tmp_path / "malicious_subproc.pkl"
    with p.open("wb") as f:
        pickle.dump(_MaliciousSubprocess(), f)
    return p


@pytest.fixture
def torch_zip_with_malicious_pickle(tmp_path: Path) -> Path:
    """Эмуляция формата torch.save() — ZIP с data.pkl внутри."""
    p = tmp_path / "model.pt"
    inner_pickle = pickle.dumps(_MaliciousOsSystem())
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("archive/data.pkl", inner_pickle)
        zf.writestr("archive/version", "3\n")
    return p


@pytest.fixture
def corrupt_pickle_path(tmp_path: Path) -> Path:
    """Битый pickle — должны получить parse-error finding."""
    p = tmp_path / "corrupt.pkl"
    p.write_bytes(b"\x80\x04\x95\xff\xff\xff\xff\xff\xff\xff\x7fGARBAGE")
    return p
