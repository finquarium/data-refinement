import hashlib

def mask_email(email: str) -> str:
    """
    Mask email addresses by hashing the local part (before @).

    Args:
        email: The email address to mask

    Returns:
        Masked email address with hashed local part
    """
    if not email or '@' not in email:
        return email

    local_part, domain = email.split('@', 1)
    hashed_local = hashlib.md5(local_part.encode()).hexdigest()

    return f"{hashed_local}@{domain}"