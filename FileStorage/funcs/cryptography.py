from argon2 import PasswordHasher
import secrets


ph = PasswordHasher()

def generate_secret() -> str:
    return secrets.token_hex(nbytes=64)

def hash_password(password:str) -> str:
    return ph.hash(password)

def validate_password(hashed_password:str, password_to_check:str) -> bool:
    try:
        return ph.verify(hashed_password, password_to_check)
    except Exception as e:
        return False
