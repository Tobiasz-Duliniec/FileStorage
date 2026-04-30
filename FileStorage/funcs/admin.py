'''
File for admin panel stuff.
'''

from flask import current_app
import funcs.config as config_funcs
import funcs.cryptography as crypto_funcs
import funcs.database as database_funcs
import funcs.funcs as funcs
import os
import uuid


def create_account(username:str, password:str, permissions:str) -> tuple[bool, str]:
    if(username is None or password is None or permissions is None):
        current_app.logger.error(f'Missing data during account creation.', {'log_type': 'account'})
        return (False, 'Please input username, password, and permissions.')
    password = crypto_funcs.hash_password(password)
    user_UUID = str(uuid.uuid4())
    status = database_funcs.add_account_to_database(username, password, user_UUID, permissions)
    if(status[0]):
        os.makedirs(os.path.join('files', user_UUID))
        current_app.logger.info(f'New account has been created: {username}', {'log_type': 'account'})
        return (True, 'New account created.')
    current_app.logger.error(f'Account creation failed: {status[1]}.', {'log_type': 'account'})
    return (False, f'Account creation failed: {status[1]}')

def is_admin(username:str) -> bool:
    if(username is None):
        return False
    permissions = database_funcs.get_user_permissions(username)
    return permissions == 1
