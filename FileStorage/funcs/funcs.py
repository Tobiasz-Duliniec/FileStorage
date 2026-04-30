'''
Various functions
'''

from flask import current_app, request
import funcs.cryptography as crypto_funcs
import funcs.database as database_funcs
import json
import logging
import os
import sqlite3
import uuid
import werkzeug


def convert_bytes_to_megabytes(size:int) -> float:
    return round((size / (1024 * 1024)), 3)

def change_password(new_password:str | None, new_password_confirmation:str | None, current_password:str | None, username:str) -> tuple[bool, str]:
    if(current_password is not None and new_password is not None and new_password_confirmation is not None and new_password == new_password_confirmation):
        new_password = crypto_funcs.hash_password(new_password)
        current_password = current_password
        current_password_correct = validate_login_data(username, current_password)
        if(current_password_correct):
            database_funcs.change_password(username, new_password)
            current_app.logger.info(f'{username} has changed their password.', {'log_type': 'account'})
            return (True, 'Password changed successfully.')
        else:
            current_app.logger.info('Password change fail: incorrect current password.', {'log_type': 'account'})
            return (False, 'Please input the correct current password')
    else:
        current_app.logger.info('Password change fail: incorrect or no account data provided.', {'log_type': 'account'})
        return (False, 'Please enter two matching passwords and your current password.')

def check_database() -> None:
    current_app.logger.info('Checking database.')
    if(not os.path.isfile(os.path.join('instance', 'users.db'))):
        create_users_database()
    else:
        current_app.logger.info('Database found.')

def create_users_database() -> None:
    '''
    Creates users database if it wasn't found during startup.
    The users database will contain only admin account with the password and username "admin".
    It is recommended that the password is changed before putting the site to production.
    '''
    current_app.logger.info('Creating users database.')
    admin_UUID = str(uuid.uuid4())
    password = crypto_funcs.hash_password('admin')
    database_funcs.create_initial_database_tables(admin_UUID, password)
    admin_file_folder = os.path.join('files', admin_UUID)
    if(not os.path.isdir(admin_file_folder)):
        os.makedirs(admin_file_folder)
    current_app.logger.info('Users database created.')

def delete_file(public_filename:str, username:str) -> tuple[bool, str]:
    user_UUID = database_funcs.get_UUID_by_username(username)
    internal_filename = database_funcs.get_internal_filename_by_uuid(public_filename, user_UUID)
    database_funcs.delete_file_from_database(public_filename, user_UUID)
    os.remove(f'files/{user_UUID}/{internal_filename}')
    current_app.logger.info(f'{username} has deleted a file: {public_filename}', {'log_type': 'file deletion'})
    return (True, 'File deleted successfully.')

def get_file_list(username:str, file_start:int) -> dict:
    user_UUID = database_funcs.get_UUID_by_username(username)
    file_list = database_funcs.get_file_list(username, current_app.config['MAX_FILES_PER_PAGE'], file_start)
    file_list = dict(
        (file[0], convert_bytes_to_megabytes(os.path.getsize(os.path.join('files', user_UUID, file[1]))))
                    for file in file_list
        )
    return file_list

def is_filename_legal(filename:str) -> bool:
    if(len(filename) > current_app.config['MAX_FILENAME_LENGTH']):
        return False
    for letter in filename:
        if(letter in current_app.config['BANNED_CHARACTERS']):
            return False
    return True

def save_file(file:werkzeug.datastructures.file_storage.FileStorage, username:str) -> tuple[bool, str]:
    if(not isinstance(file, werkzeug.datastructures.file_storage.FileStorage)):
        return (False, "File wasn't passed as a parameter for the function.")
    filename = file.filename
    if(filename == ''):
        current_app.logger.info(f"{username} tried saving file but didn't send any.", {'log_type': 'file save'})
        return (False, 'Failed to save the file: no file found.')
    if(not is_filename_legal(filename)):
        current_app.logger.info(f'{username} tried saving file with an invalid filename: {filename}', {'log_type': 'file save'})
        return (False, 'Invalid filename: filename contains illegal characters or is too long.')
    is_filename_taken = database_funcs.test_for_public_filename(filename, username)
    if(is_filename_taken):
        cur.close()
        current_app.logger.info(f'{username} tried saving file with an existing filename: {filename}', {'log_type': 'file save'})
        return (False, "Couldn't save the file: file with such name already exists.")
    uploader_UUID = database_funcs.get_UUID_by_username(username)
    internal_filename = str(uuid.uuid4())
    database_funcs.add_file_to_database(filename, internal_filename, uploader_UUID)
    file.save(os.path.join('files', uploader_UUID, internal_filename))
    current_app.logger.info(f'{username} has saved a new file on the server: {filename}', {'log_type': 'file save'})
    return (True, 'File has been saved on the server.')

def share_file(filename:str, username:str) -> tuple[bool, str]:
    file_shared = database_funcs.test_for_shared_file(filename, username)
    if(file_shared):
        current_app.logger.info(f'{username} has tried to share an already shared file: {filename}', {'log_type': 'file share'})
        return (False, 'Error: this file is already shared!')
    else:
        internal_filename = database_funcs.get_internal_filename_by_username(filename, username)
        share_url = str(uuid.uuid4())
        database_funcs.add_share_to_database(internal_filename, share_url)
        current_app.logger.info(f'{username} has shared a new file: {filename}', {'log_type': 'file share'})
        return (True, f'File shared! Share URL is: {request.url_root}shared_files/{share_url}')

def unshare_file(filename:str, username:str) -> tuple[bool, str]:
    share_url = database_funcs.get_share_url(filename, username)
    if(share_url is None):
        current_app.logger.info(f'{username} tried to stop sharing a file that was not shared', {'log_type': 'file share'})
        return (False, 'File is not shared!')
    database_funcs.delete_share(share_url[0])
    current_app.logger.info(f'{username} has stopped sharing {filename}', {'log_type': 'file share'})
    return (True, 'File unshared.')

def validate_login_data(username:str, password:str) -> bool:
    correct_password = database_funcs.get_database_password(username)
    if(correct_password is None):
        crypto_funcs.validate_password('$argon2id$v=19$m=65536,t=3,p=4$lJRRaKsBXe1G+p9uRsjKXw$nJrqCkcUJLXc2doBxsu6tjWgoVdaZp1dsECZXmM5GBw', password)
        # dummy hashing to protect against timing attacks
        current_app.logger.info(f'Failed log in attempt as {username}.', {'log_type': 'log in attempt'})
        return False
    else:
        if(crypto_funcs.validate_password(correct_password[0], password, username)):
            current_app.logger.info(f'Successful log in attempt as {username}.', {'log_type': 'log in attempt'})
            return True
        else:
            current_app.logger.info(f'Failed log in attempt as {username}.', {'log_type': 'log in attempt'})
            return False
