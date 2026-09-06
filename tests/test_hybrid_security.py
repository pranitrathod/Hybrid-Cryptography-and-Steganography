import io
import unittest

from PIL import Image

from crud.services.hybrid_security import (
    HybridSecurityError,
    encrypt_and_embed,
    extract_and_decrypt,
    generate_recipient_keypair,
    lzw_compress,
    lzw_decompress,
)


def cover_image(width=160, height=160):
    image = Image.new("RGB", (width, height), color=(120, 150, 180))
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


class HybridSecurityTests(unittest.TestCase):
    def test_round_trip_encrypts_embeds_extracts_and_verifies(self):
        private_key, public_key = generate_recipient_keypair()
        source = (b"Confidential cloud payload. " * 30) + bytes(range(32))

        protected = encrypt_and_embed(source, cover_image(), public_key)
        recovered = extract_and_decrypt(protected.image_bytes, private_key)

        self.assertEqual(recovered, source)
        self.assertEqual(len(protected.sha256), 64)

    def test_lzw_round_trip(self):
        source = b"TOBEORNOTTOBEORTOBEORNOT"
        self.assertEqual(lzw_decompress(lzw_compress(source)), source)

    def test_rejects_cover_image_without_capacity(self):
        _, public_key = generate_recipient_keypair()
        with self.assertRaisesRegex(HybridSecurityError, "capacity"):
            encrypt_and_embed(b"payload", cover_image(1, 1), public_key)

    def test_rejects_wrong_recipient_key(self):
        correct_private, public_key = generate_recipient_keypair()
        wrong_private, _ = generate_recipient_keypair()
        protected = encrypt_and_embed(b"confidential", cover_image(), public_key)

        self.assertEqual(extract_and_decrypt(protected.image_bytes, correct_private), b"confidential")
        with self.assertRaises(HybridSecurityError):
            extract_and_decrypt(protected.image_bytes, wrong_private)


if __name__ == "__main__":
    unittest.main()
