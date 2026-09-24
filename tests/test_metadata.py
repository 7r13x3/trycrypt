import json
import pytest
from pathlib import Path

from trycrypt.vault import CryptomatorVault
from trycrypt.analysis.metadata import analyze_metadata


@pytest.fixture
def populated_vault(tmp_path):
    vault = tmp_path / "vault"
    data = vault / "d" / "AB" / "1234567890abcdef"
    data.mkdir(parents=True)

    (vault / "masterkey.cryptomator").write_text(json.dumps({
        "version": 999,
        "scryptSalt": "AAAA",
        "scryptCostParam": 16384,
        "scryptBlockSize": 8,
    }))
    (vault / "vault.cryptomator").write_text("jwt-token")

    # Files spanning multiple size buckets
    sizes = [500, 50_000, 800_000, 5_000_000, 80_000_000]
    for i, size in enumerate(sizes):
        (data / f"file{i}.c9r").write_bytes(b"\x00" * size)

    return vault


def test_metadata_basic(populated_vault):
    v = CryptomatorVault(populated_vault)
    result = analyze_metadata(v)

    assert result["total_files"] == 5
    assert result["total_bytes"] > 0
    assert "entropy" in result
    assert 0.0 <= result["entropy"]["normalized"] <= 1.0


def test_metadata_fingerprints(populated_vault):
    v = CryptomatorVault(populated_vault)
    result = analyze_metadata(v)
    fp = result["fingerprints"]
    # 500B file -> tiny_config or small_document
    assert any(k in fp for k in ("tiny_config", "small_document"))
    # 80MB file -> large_image_video or video_archive
    assert any(k in fp for k in ("large_image_video", "video_archive"))


def test_metadata_empty_vault(tmp_path):
    vault = tmp_path / "empty"
    (vault / "d").mkdir(parents=True)
    (vault / "masterkey.cryptomator").write_text("{}")
    (vault / "vault.cryptomator").write_text("")

    v = CryptomatorVault(vault)
    result = analyze_metadata(v)
    assert "error" in result
