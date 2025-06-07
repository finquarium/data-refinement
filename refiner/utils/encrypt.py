import pgpy
from pgpy.constants import CompressionAlgorithm, HashAlgorithm
import os
from refiner.config import settings


def encrypt_file(encryption_key: str, file_path: str, output_path: str = None) -> str:
    """Symmetrically encrypts a file with an encryption key.

    Args:
        encryption_key: The passphrase to encrypt with
        file_path: Path to the file to encrypt
        output_path: Optional path to save encrypted file (defaults to file_path + .pgp)

    Returns:
        Path to encrypted file
    """
    if not encryption_key:
        raise ValueError("REFINEMENT_ENCRYPTION_KEY cannot be empty for encryption.")

    if output_path is None:
        output_path = f"{file_path}.pgp"

    with open(file_path, 'rb') as f:
        buffer = f.read()

    message = pgpy.PGPMessage.new(buffer, compression=CompressionAlgorithm.ZLIB)
    encrypted_message = message.encrypt(
        passphrase=encryption_key, hash=HashAlgorithm.SHA512
    )

    with open(output_path, 'wb') as f:
        f.write(str(encrypted_message).encode())

    return output_path


def decrypt_file(encryption_key: str, file_path: str, output_path: str = None) -> str:
    """Symmetrically decrypts a file with an encryption key.

    Args:
        encryption_key: The passphrase to decrypt with
        file_path: Path to the encrypted file
        output_path: Optional path to save decrypted file (defaults to file_path without .pgp)

    Returns:
        Path to decrypted file
    """
    if not encryption_key:
        raise ValueError("REFINEMENT_ENCRYPTION_KEY cannot be empty for decryption.")

    if output_path is None:
        if file_path.endswith('.pgp'):
            output_path = f"{file_path[:-4]}.decrypted"  # Remove .pgp extension
        else:
            output_path = f"{file_path}.decrypted"

    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    message = pgpy.PGPMessage.from_blob(encrypted_data)
    decrypted_message = message.decrypt(encryption_key)

    with open(output_path, 'wb') as f:
        f.write(decrypted_message.message)

    return output_path

# Test with: python -m refiner.utils.encrypt (ensure .env has REFINEMENT_ENCRYPTION_KEY)
if __name__ == "__main__":
    if not os.path.exists(settings.OUTPUT_DIR):
        os.makedirs(settings.OUTPUT_DIR)

    plaintext_db_content = "This is a test database content."
    plaintext_db_path = os.path.join(settings.OUTPUT_DIR, "test_db.libsql")
    with open(plaintext_db_path, 'w') as f:
        f.write(plaintext_db_content)

    if not settings.REFINEMENT_ENCRYPTION_KEY:
        print("Error: REFINEMENT_ENCRYPTION_KEY not set in environment or .env file for testing.")
    else:
        print(f"Using encryption key: {settings.REFINEMENT_ENCRYPTION_KEY[:5]}...") # Print only a part for safety
        # Encrypt and decrypt
        encrypted_path = encrypt_file(settings.REFINEMENT_ENCRYPTION_KEY, plaintext_db_path)
        print(f"File encrypted to: {encrypted_path}")

        decrypted_path = decrypt_file(settings.REFINEMENT_ENCRYPTION_KEY, encrypted_path)
        print(f"File decrypted to: {decrypted_path}")
        with open(decrypted_path, 'r') as f_dec:
            decrypted_content = f_dec.read()
        assert decrypted_content == plaintext_db_content
        print("Encryption and decryption test successful.")

        # Clean up test files
        os.remove(plaintext_db_path)
        os.remove(encrypted_path)
        os.remove(decrypted_path)