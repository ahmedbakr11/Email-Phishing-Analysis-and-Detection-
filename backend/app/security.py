import base64
import binascii
import os
from pathlib import Path
from threading import Lock
from typing import Iterable, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class DecryptionError(Exception):
    """Raised when decryption fails for data that appears encrypted."""


_KEY_LOCK = Lock()
_PRIVATE_KEY = None
_PUBLIC_KEY_PEM = None

_DEFAULT_KEY_DIR = Path(
    os.environ.get(
        "RSA_KEY_DIR",
        Path(__file__).resolve().parent.parent / "keys",
    )
)
_PRIVATE_KEY_PATH = Path(
    os.environ.get("RSA_PRIVATE_KEY_PATH", _DEFAULT_KEY_DIR / "private_key.pem")
)
_PUBLIC_KEY_PATH = Path(
    os.environ.get("RSA_PUBLIC_KEY_PATH", _DEFAULT_KEY_DIR / "public_key.pem")
)


def _load_key_from_env(var_name: str) -> Optional[bytes]:
    """Return the raw PEM value from either a *_PATH or direct env var."""
    path_value = os.environ.get(f"{var_name}_PATH")
    if path_value:
        path = Path(path_value)
        if path.exists():
            return path.read_bytes()

    raw_value = os.environ.get(var_name)
    if raw_value:
        return raw_value.encode("utf-8")

    return None


def _ensure_key_dir() -> None:
    if not _DEFAULT_KEY_DIR.exists():
        _DEFAULT_KEY_DIR.mkdir(parents=True, exist_ok=True)


def _persist_key_material(private_key_pem: bytes, public_key_pem: bytes) -> None:
    """Write generated key material to disk when file paths are configured."""
    _ensure_key_dir()
    if _PRIVATE_KEY_PATH:
        _PRIVATE_KEY_PATH.write_bytes(private_key_pem)
        try:
            os.chmod(_PRIVATE_KEY_PATH, 0o600)
        except OSError:
            pass
    if _PUBLIC_KEY_PATH:
        _PUBLIC_KEY_PATH.write_bytes(public_key_pem)
        try:
            os.chmod(_PUBLIC_KEY_PATH, 0o644)
        except OSError:
            pass


def _load_private_key() -> rsa.RSAPrivateKey:
    pem_bytes = _load_key_from_env("RSA_PRIVATE_KEY")
    if pem_bytes is None and _PRIVATE_KEY_PATH.exists():
        pem_bytes = _PRIVATE_KEY_PATH.read_bytes()

    if pem_bytes:
        return serialization.load_pem_private_key(pem_bytes, password=None)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _persist_key_material(private_pem, public_pem)
    return private_key


def _load_public_key_pem(private_key) -> str:
    pem_bytes = _load_key_from_env("RSA_PUBLIC_KEY")
    if pem_bytes is None and _PUBLIC_KEY_PATH.exists():
        pem_bytes = _PUBLIC_KEY_PATH.read_bytes()

    if pem_bytes:
        return pem_bytes.decode("utf-8").strip()

    return (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
        .strip()
    )


def _initialise_keys() -> None:
    global _PRIVATE_KEY, _PUBLIC_KEY_PEM

    if _PRIVATE_KEY is not None and _PUBLIC_KEY_PEM is not None:
        return

    with _KEY_LOCK:
        if _PRIVATE_KEY is not None and _PUBLIC_KEY_PEM is not None:
            return

        private_key = _load_private_key()
        public_key_pem = _load_public_key_pem(private_key)

        _PRIVATE_KEY = private_key
        _PUBLIC_KEY_PEM = public_key_pem


def get_public_key_pem() -> str:
    """Return the PEM-encoded RSA public key."""
    _initialise_keys()
    return _PUBLIC_KEY_PEM


def _try_decrypt_value(encrypted_value: str) -> Optional[str]:
    """Attempt to decrypt the provided value; return plaintext or None if it fails."""
    if not encrypted_value:
        return None

    _initialise_keys()

    try:
        ciphertext = base64.b64decode(encrypted_value)
    except (ValueError, binascii.Error):
        return None

    try:
        plaintext_bytes = _PRIVATE_KEY.decrypt(
            ciphertext,
            padding.PKCS1v15(),
        )
    except ValueError:
        return None

    return plaintext_bytes.decode("utf-8")


def decrypt_sensitive_fields(data: dict, field_names: Iterable[str]) -> None:
    """In-place decryption of credential fields, leaving values untouched when not encrypted."""
    if not isinstance(data, dict):
        return

    for field in field_names:
        value = data.get(field)
        if not isinstance(value, str):
            continue

        decrypted_value = _try_decrypt_value(value)
        if decrypted_value is not None:
            data[field] = decrypted_value
        elif len(value) > 60:
            raise DecryptionError(f"Failed to decrypt field '{field}'.")
