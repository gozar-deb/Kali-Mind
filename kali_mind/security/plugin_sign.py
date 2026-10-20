"""Cryptographic plugin signing (HMAC-SHA256 + optional Ed25519).

Signing key from env ``KALI_MIND_PLUGIN_SIGNING_KEY`` (HMAC) or
``KALI_MIND_PLUGIN_SIGNING_PRIVKEY`` / ``KALI_MIND_PLUGIN_SIGNING_PUBKEY`` (PEM).
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


def _canonical_bytes(plugin_dir: Path) -> bytes:
    """Hash file contents in sorted order for stable signatures."""
    h = hashlib.sha256()
    root = plugin_dir.resolve()
    for path in sorted(plugin_dir.rglob("*")):
        # Never follow plugin-controlled symlinks into files outside the signed tree.
        if path.is_symlink() or not path.is_file():
            continue
        try:
            path.resolve().relative_to(root)
        except ValueError:
            continue
        if path.name in {"signature.hmac", "signature.ed25519", "checksums.sha256"}:
            continue
        rel = path.relative_to(plugin_dir).as_posix()
        h.update(rel.encode())
        h.update(b"\0")
        h.update(path.read_bytes())
        h.update(b"\0")
    return h.digest()


def sign_plugin_hmac(plugin_dir: Path, key: Optional[str] = None) -> Path:
    key = key or os.getenv("KALI_MIND_PLUGIN_SIGNING_KEY")
    if not key or key == "dev-only-insecure-key":
        raise ValueError("Set KALI_MIND_PLUGIN_SIGNING_KEY to a strong secret before signing plugins")
    digest = _canonical_bytes(plugin_dir)
    sig = hmac.new(key.encode(), digest, hashlib.sha256).hexdigest()
    out = plugin_dir / "signature.hmac"
    out.write_text(sig + "\n")
    return out


def verify_plugin_hmac(plugin_dir: Path, key: Optional[str] = None) -> Tuple[bool, str]:
    key = key or os.getenv("KALI_MIND_PLUGIN_SIGNING_KEY")
    sig_path = plugin_dir / "signature.hmac"
    if sig_path.is_symlink():
        return False, "signature file must not be a symlink"
    if not sig_path.exists():
        return False, "missing signature.hmac"
    if not key:
        return False, "KALI_MIND_PLUGIN_SIGNING_KEY not set"
    expected = sig_path.read_text().strip()
    digest = _canonical_bytes(plugin_dir)
    actual = hmac.new(key.encode(), digest, hashlib.sha256).hexdigest()
    if hmac.compare_digest(expected, actual):
        return True, "HMAC signature valid"
    return False, "HMAC signature mismatch"


def sign_plugin_ed25519(plugin_dir: Path, privkey_pem: Optional[str] = None) -> Optional[Path]:
    """Sign with Ed25519 if cryptography is installed."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        logger.debug("cryptography not installed; Ed25519 signing unavailable")
        return None
    pem = privkey_pem or os.getenv("KALI_MIND_PLUGIN_SIGNING_PRIVKEY")
    if not pem:
        return None
    try:
        key_path = Path(pem)
        is_file = "\n" not in pem and key_path.is_file()
    except OSError:
        is_file = False
        key_path = None
    if is_file and key_path is not None:
        pem_bytes = key_path.read_bytes()
    else:
        pem_bytes = pem.encode()
    key = serialization.load_pem_private_key(pem_bytes, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Not an Ed25519 private key")
    sig = key.sign(_canonical_bytes(plugin_dir))
    out = plugin_dir / "signature.ed25519"
    out.write_bytes(sig)
    return out


def verify_plugin_ed25519(plugin_dir: Path, pubkey_pem: Optional[str] = None) -> Tuple[bool, str]:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return False, "cryptography not installed"
    pem = pubkey_pem or os.getenv("KALI_MIND_PLUGIN_SIGNING_PUBKEY")
    sig_path = plugin_dir / "signature.ed25519"
    if sig_path.is_symlink():
        return False, "signature file must not be a symlink"
    if not sig_path.exists():
        return False, "missing signature.ed25519"
    if not pem:
        return False, "KALI_MIND_PLUGIN_SIGNING_PUBKEY not set"
    try:
        key_path = Path(pem)
        is_file = "\n" not in pem and key_path.is_file()
    except OSError:
        is_file = False
        key_path = None
    if is_file and key_path is not None:
        pem_bytes = key_path.read_bytes()
    else:
        pem_bytes = pem.encode()
    key = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(key, Ed25519PublicKey):
        return False, "Not an Ed25519 public key"
    try:
        key.verify(sig_path.read_bytes(), _canonical_bytes(plugin_dir))
        return True, "Ed25519 signature valid"
    except Exception as e:
        return False, f"Ed25519 verify failed: {e}"


def verify_plugin_signature(plugin_dir: Path, *, require: bool = True) -> Tuple[bool, str]:
    """Try Ed25519 then HMAC. If require=False and no sig file, allow with warning."""
    if (plugin_dir / "signature.ed25519").exists():
        return verify_plugin_ed25519(plugin_dir)
    if (plugin_dir / "signature.hmac").exists():
        return verify_plugin_hmac(plugin_dir)
    if require:
        return False, "plugin signature required but missing"
    return True, "no signature (allowed)"
