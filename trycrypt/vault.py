from pathlib import Path
from typing import Iterator
import json
from .models import MasterkeyFile


class CryptomatorVault:
    """
    Represents a Cryptomator vault on disk.
    Vault format: masterkey.cryptomator + vault.cryptomator + d/ (encrypted data)
    """

    def __init__(self, path: Path):
        self.path = Path(path).resolve()
        self.masterkey_path = self.path / "masterkey.cryptomator"
        self.config_path = self.path / "vault.cryptomator"
        self.data_dir = self.path / "d"

    def validate(self) -> bool:
        return (
            self.path.is_dir()
            and self.masterkey_path.is_file()
            and self.config_path.is_file()
            and self.data_dir.is_dir()
        )

    def parse_masterkey(self) -> MasterkeyFile:
        raw = json.loads(self.masterkey_path.read_text())
        return MasterkeyFile.model_validate(raw)

    def iter_encrypted_files(self) -> Iterator[Path]:
        """
        Yields every .c9r (encrypted content) file in the vault.
        Structure: d/XX/YYYYYYYY-.../filename.c9r
        """
        if not self.data_dir.exists():
            return
        for lvl1 in self.data_dir.iterdir():
            if not lvl1.is_dir():
                continue
            for lvl2 in lvl1.iterdir():
                if not lvl2.is_dir():
                    continue
                for f in lvl2.iterdir():
                    if f.is_file() and f.suffix == ".c9r":
                        yield f
