"""End-to-end hybrid encryption and LSB steganography workflow.

The pipeline is intentionally independent from HTTP views so it can be called by a Django
upload handler, a worker, or a command-line task:

plain file -> SHA-256 -> LZW -> AES-GCM -> LSB PNG -> storage
LSB PNG -> AES-GCM -> LZW -> SHA-256 verification -> plain file
"""

from __future__ import annotations

import hashlib
import io
import os
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from PIL import Image

_MAGIC = b"HCS1"
_VERSION = 1
_HEADER = struct.Struct(">4sB32s65s12sI")


class HybridSecurityError(ValueError):
    """Raised when a stego payload is malformed, too large, or fails verification."""


@dataclass(frozen=True)
class EncryptedStegoFile:
    """The PNG bytes ready to be stored and the source file integrity hash."""

    image_bytes: bytes
    sha256: str


def generate_recipient_keypair() -> tuple[bytes, bytes]:
    """Return PEM-encoded ECC private and public keys for a recipient."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def encrypt_and_embed(plaintext: bytes, cover_image: bytes, recipient_public_key: bytes) -> EncryptedStegoFile:
    """Encrypt data for a recipient and embed the encrypted payload in a PNG cover image."""
    if not plaintext:
        raise HybridSecurityError("The file to protect cannot be empty.")

    recipient_key = serialization.load_pem_public_key(recipient_public_key)
    if not isinstance(recipient_key, ec.EllipticCurvePublicKey) or not isinstance(
        recipient_key.curve, ec.SECP256R1
    ):
        raise HybridSecurityError("The recipient key must use the P-256 ECC curve.")

    original_hash = hashlib.sha256(plaintext).digest()
    compressed = lzw_compress(plaintext)
    ephemeral_key = ec.generate_private_key(ec.SECP256R1())
    aes_key = _derive_aes_key(ephemeral_key.exchange(ec.ECDH(), recipient_key))
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, compressed, original_hash)
    ephemeral_public = ephemeral_key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    payload = _HEADER.pack(_MAGIC, _VERSION, original_hash, ephemeral_public, nonce, len(ciphertext)) + ciphertext
    return EncryptedStegoFile(embed_lsb(cover_image, payload), original_hash.hex())


def extract_and_decrypt(stego_image: bytes, recipient_private_key: bytes) -> bytes:
    """Extract, decrypt, decompress, and authenticate an embedded encrypted file."""
    payload = extract_lsb(stego_image)
    if len(payload) < _HEADER.size:
        raise HybridSecurityError("The stego image does not contain a complete payload.")

    magic, version, expected_hash, ephemeral_public, nonce, ciphertext_length = _HEADER.unpack(
        payload[: _HEADER.size]
    )
    if magic != _MAGIC or version != _VERSION:
        raise HybridSecurityError("The stego image does not contain a supported payload.")
    ciphertext = payload[_HEADER.size :]
    if len(ciphertext) != ciphertext_length:
        raise HybridSecurityError("The stego payload length is invalid.")

    private_key = serialization.load_pem_private_key(recipient_private_key, password=None)
    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(
        private_key.curve, ec.SECP256R1
    ):
        raise HybridSecurityError("The recipient key must use the P-256 ECC curve.")
    try:
        ephemeral_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ephemeral_public)
        aes_key = _derive_aes_key(private_key.exchange(ec.ECDH(), ephemeral_key))
        plaintext = lzw_decompress(AESGCM(aes_key).decrypt(nonce, ciphertext, expected_hash))
    except Exception as error:
        raise HybridSecurityError("Unable to decrypt or authenticate the stego payload.") from error

    if hashlib.sha256(plaintext).digest() != expected_hash:
        raise HybridSecurityError("SHA-256 integrity verification failed.")
    return plaintext


def lzw_compress(data: bytes) -> bytes:
    """Compress bytes using a deterministic 16-bit LZW stream."""
    dictionary = {bytes([value]): value for value in range(256)}
    next_code = 256
    phrase = b""
    codes: list[int] = []
    for byte in data:
        candidate = phrase + bytes([byte])
        if candidate in dictionary:
            phrase = candidate
            continue
        codes.append(dictionary[phrase])
        if next_code > 65535:
            raise HybridSecurityError("Input is too varied for the 16-bit LZW dictionary.")
        dictionary[candidate] = next_code
        next_code += 1
        phrase = bytes([byte])
    if phrase:
        codes.append(dictionary[phrase])
    return b"".join(struct.pack(">H", code) for code in codes)


def lzw_decompress(data: bytes) -> bytes:
    """Restore a 16-bit LZW stream emitted by :func:`lzw_compress`."""
    if not data or len(data) % 2:
        raise HybridSecurityError("The LZW stream is invalid.")
    codes = [struct.unpack(">H", data[index : index + 2])[0] for index in range(0, len(data), 2)]
    dictionary = {value: bytes([value]) for value in range(256)}
    next_code = 256
    phrase = dictionary.get(codes[0])
    if phrase is None:
        raise HybridSecurityError("The LZW stream starts with an invalid code.")
    output = bytearray(phrase)
    for code in codes[1:]:
        entry = dictionary.get(code, phrase + phrase[:1] if code == next_code else None)
        if entry is None:
            raise HybridSecurityError("The LZW stream contains an invalid code.")
        output.extend(entry)
        if next_code <= 65535:
            dictionary[next_code] = phrase + entry[:1]
            next_code += 1
        phrase = entry
    return bytes(output)


def embed_lsb(cover_image: bytes, payload: bytes) -> bytes:
    """Embed a length-prefixed byte payload into RGB LSBs and return a lossless PNG."""
    image = Image.open(io.BytesIO(cover_image)).convert("RGB")
    framed_payload = struct.pack(">I", len(payload)) + payload
    bits = _bits(framed_payload)
    if len(bits) > image.width * image.height * 3:
        raise HybridSecurityError("The cover image does not have enough LSB capacity.")

    pixels = list(image.getdata())
    changed = []
    bit_index = 0
    for pixel in pixels:
        channels = list(pixel)
        for channel in range(3):
            if bit_index < len(bits):
                channels[channel] = (channels[channel] & 0xFE) | bits[bit_index]
                bit_index += 1
        changed.append(tuple(channels))
    image.putdata(changed)
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def extract_lsb(stego_image: bytes) -> bytes:
    """Extract the length-prefixed payload from a PNG's RGB least-significant bits."""
    image = Image.open(io.BytesIO(stego_image)).convert("RGB")
    bits = [channel & 1 for pixel in image.getdata() for channel in pixel]
    if len(bits) < 32:
        raise HybridSecurityError("The image is too small to contain a payload.")
    payload_length = _from_bits(bits[:32])
    available = (len(bits) - 32) // 8
    if payload_length > available:
        raise HybridSecurityError("The image payload length exceeds its LSB capacity.")
    return bytes(_from_bits(bits[index : index + 8]) for index in range(32, 32 + payload_length * 8, 8))


def _derive_aes_key(shared_secret: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"hybrid-cloud-data-v1").derive(shared_secret)


def _bits(data: bytes) -> list[int]:
    return [(byte >> shift) & 1 for byte in data for shift in range(7, -1, -1)]


def _from_bits(bits: list[int]) -> int:
    value = 0
    for bit in bits:
        value = (value << 1) | bit
    return value
