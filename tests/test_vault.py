import json
import pytest
from pathlib import Path

from trycrypt.vault import CryptomatorVault


@pytest.fixture
def fake_vault(tmp_path):
    """Build a minimal fake Cryptomator vault in a temp directory."""
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

    for i, size in enumerate([1024, 200_000, 5_000_000]):
        (data / f"file{i}.c9r").write_bytes(b"\x00" * size)

    return vault


def test_vault_validate_ok(fake_vault):
    v = CryptomatorVault(fake_vault)
    assert v.validate() is True


def test_vault_validate_missing_masterkey(tmp_path):
    v = CryptomatorVault(tmp_path)
    assert v.validate() is False


def test_parse_masterkey(fake_vault):
    v = CryptomatorVault(fake_vault)
    mk = v.parse_masterkey()
    assert mk.version == 999
    assert mk.scrypt_params.cost_param == 16384
    assert mk.scrypt_params.block_size == 8


def test_iter_encrypted_files(fake_vault):
    v = CryptomatorVault(fake_vault)
    files = list(v.iter_encrypted_files())
    assert len(files) == 3
    assert all(f.suffix == ".c9r" for f in files)
