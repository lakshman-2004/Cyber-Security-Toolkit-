"""
Module 3: Hash Generator
Generate cryptographic hash values for text or files.
Supported algorithms: MD5, SHA1, SHA224, SHA256, SHA384, SHA512
"""

import hashlib
import os


SUPPORTED_ALGORITHMS = ["MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512"]

_ALG_MAP = {
    "MD5":    "md5",
    "SHA1":   "sha1",
    "SHA224": "sha224",
    "SHA256": "sha256",
    "SHA384": "sha384",
    "SHA512": "sha512",
}


def hash_text(text: str, algorithm: str) -> dict:
    """
    Hash a plain-text string.

    Returns:
        {
            "algorithm": str,
            "input_type": "text",
            "digest": str,          # hex digest
            "digest_length": int,   # bits
            "success": bool,
            "error": str | None,
        }
    """
    alg_key = algorithm.upper()
    if alg_key not in _ALG_MAP:
        return _error_result(algorithm, f"Unsupported algorithm: {algorithm}")

    try:
        h = hashlib.new(_ALG_MAP[alg_key])
        h.update(text.encode("utf-8"))
        digest = h.hexdigest()
        return {
            "algorithm":    alg_key,
            "input_type":   "text",
            "digest":       digest,
            "digest_length": h.digest_size * 8,
            "success":      True,
            "error":        None,
        }
    except Exception as exc:
        return _error_result(algorithm, str(exc))


def hash_file(filepath: str, algorithm: str) -> dict:
    """
    Hash a file by reading it in chunks (handles large files).

    Returns same structure as hash_text plus:
        "filename": str
        "filesize": int  (bytes)
    """
    alg_key = algorithm.upper()
    if alg_key not in _ALG_MAP:
        return _error_result(algorithm, f"Unsupported algorithm: {algorithm}")

    if not os.path.isfile(filepath):
        return _error_result(algorithm, f"File not found: {filepath}")

    try:
        h = hashlib.new(_ALG_MAP[alg_key])
        filesize = os.path.getsize(filepath)
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        digest = h.hexdigest()
        return {
            "algorithm":    alg_key,
            "input_type":   "file",
            "filename":     os.path.basename(filepath),
            "filesize":     filesize,
            "digest":       digest,
            "digest_length": h.digest_size * 8,
            "success":      True,
            "error":        None,
        }
    except Exception as exc:
        return _error_result(algorithm, str(exc))


def hash_text_all(text: str) -> dict:
    """Return hashes for all supported algorithms at once."""
    return {alg: hash_text(text, alg)["digest"] for alg in SUPPORTED_ALGORITHMS}


def hash_file_all(filepath: str) -> dict:
    """Return file hashes for all supported algorithms at once."""
    results = {}
    for alg in SUPPORTED_ALGORITHMS:
        r = hash_file(filepath, alg)
        results[alg] = r["digest"] if r["success"] else f"Error: {r['error']}"
    return results


# -- helpers ------------------------------------------------------------------

def _error_result(algorithm: str, message: str) -> dict:
    return {
        "algorithm":    algorithm.upper(),
        "input_type":   "unknown",
        "digest":       "",
        "digest_length": 0,
        "success":      False,
        "error":        message,
    }
