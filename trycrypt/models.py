from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class ScryptParams(BaseModel):
    """Cryptomator KDF parameters extracted from masterkey.cryptomator."""
    salt: str = Field(alias="scryptSalt")
    cost_param: int = Field(alias="scryptCostParam")
    block_size: int = Field(alias="scryptBlockSize")

    model_config = {"populate_by_name": True, "extra": "allow"}


class MasterkeyFile(BaseModel):
    """Validated schema for masterkey.cryptomator."""
    version: int
    scrypt_params: Optional[ScryptParams] = None

    model_config = {"populate_by_name": True, "extra": "allow"}


class FileRecord(BaseModel):
    """A single encrypted file in the vault."""
    path: str
    size: int
    mtime: datetime
    ctime: datetime
