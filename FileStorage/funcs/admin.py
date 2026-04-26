'''
File for admin panel stuff.
'''

from flask import current_app
import funcs.config as config_funcs
import funcs.cryptography as crypto_funcs
import funcs.funcs as funcs
import os
import sqlite3
import uuid


def create_account(username:str, password:str, permissions:str) -> tuple[bool, str]:
    if(username is None or password is None or permissions is None):
        current_app.logger.error(f'Missing data during account creation.', {'log_type': 'account'})
        return (False, 'Please input username, password, and permissions.')
    password = cryptofuncs.hash_password(password)
    user_UUID = str(uuid.uuid4())
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        try:
            cur.execute('INSERT INTO users(username, password, UUID, permissions) VALUES (?, ?, ?, ?)', (username, password, user_UUID, permissions))
            cur.close()
            os.makedirs(os.path.join('files', user_UUID))
            current_app.logger.info(f'New account has been created: {username}', {'log_type': 'account'})
            return (True, 'New account created.')
        except sqlite3.IntegrityError as e:
            cur.close()
            current_app.logger.error(f'Account creation failed: {e}.', {'log_type': 'account'})
            return (False, f'Account creation failed: {e}')

def is_admin(username:str) -> bool:
    if(username is None):
        return False
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        permissions = cur.execute('''SELECT permissions
                            FROM users
                            WHERE username=?;''',
                            (username, )).fetchone()[0]
        cur.close()
    return permissions == 1
