'''
Cryptography functions
'''

import argon2
import funcs.database as database_funcs
import secrets


ph = argon2.PasswordHasher()

def generate_secret() -> str:
    return secrets.token_hex(nbytes=64)

def hash_password(password:str) -> str:
    return ph.hash(password)

def validate_password(hashed_password:str, password_to_check:str, username:str|bool = False) -> bool:
    '''
    checks if a hashed password matches plaintext password.
    can pass an optional parameter of username to update the password
    in the database in case it needs rehash
    '''
    try:
        is_password_correct = ph.verify(hashed_password, password_to_check)
        if(is_password_correct and username and isinstance(username, str) and ph.check_needs_rehash(hashed_password)):
            database_funcs.change_database_password(username, ph.hash(password_to_check))
        return is_password_correct
    except (argon2.exceptions.VerificationError, argon2.exceptions.VerifyMismatchError, \
           argon2.exceptions.InvalidHashError):
        return False
