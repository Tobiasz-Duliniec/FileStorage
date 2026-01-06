'''
Different functions used by multiple files
'''

from bs4 import BeautifulSoup
from flask import current_app, request
import bcrypt
import json
import logging
import os
import sqlite3
import uuid
import werkzeug


def change_password(new_password:str | None, new_password_confirmation:str | None, current_password:str | None, username:str) -> tuple[bool, str]:
    if(current_password is not None and new_password is not None and new_password_confirmation is not None and new_password == new_password_confirmation):
        new_password = bcrypt.hashpw(new_password.encode('utf-8'), current_app.config['GENSALT'])
        current_password = bcrypt.hashpw(current_password.encode('utf-8'), current_app.config['GENSALT'])
        with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
            cur = conn.cursor()
            current_password_correct = (cur.execute('''
                        SELECT count(*)
                        FROM users
                        WHERE username = ?
                        AND password = ?''',
                        (username, current_password)).fetchone()[0]
                        == 1)
            if(current_password_correct):
                cur.execute('''UPDATE users
                                SET password = ?
                                WHERE username = ?
                                AND password = ?''',
                            (new_password, username, current_password))
                cur.close()
                conn.commit()
                current_app.logger.info(f'{username} has changed their password.', {'log_type': 'account'})
                return (True, 'Password changed successfully.')
            else:
                cur.close()
                conn.commit()
                current_app.logger.info('Password change fail: incorrect current password.', {'log_type': 'account'})
                return (False, 'Please input the correct current password')
    else:
        current_app.logger.info('Password change fail: incorrect or no account data provided.', {'log_type': 'account'})
        return (False, 'Please enter two matching passwords and your current password.')

def delete_file(filename:str, username:str) -> tuple[bool, str]:
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        cur.execute('PRAGMA foreign_keys = ON;')
        user_UUID = cur.execute('SELECT UUID FROM users WHERE username=? LIMIT 1', (username, )).fetchone()[0]
        internal_filename = cur.execute('SELECT internalFilename FROM files WHERE publicFilename=? AND UUID=? LIMIT 1', (filename, user_UUID)).fetchone()[0]
        cur.execute('DELETE FROM files WHERE publicFilename=? AND UUID=?', (filename, user_UUID))
        conn.commit()
        cur.close()
    os.remove(f'files/{user_UUID}/{internal_filename}')
    current_app.logger.info(f'{username} has deleted a file: {filename}', {'log_type': 'file deletion'})
    return (True, 'File deleted successfully.')

def get_configs() -> dict:
    config_data = {}
    with open('configurable_data.xml', 'rt', encoding = 'UTF-8') as file:
        parsed_file = BeautifulSoup(file, 'xml')
        for element in parsed_file.find_all('config'):
            config_name = element.find('name').text
            config_type = element.find('type').text
            config_data[config_name] = config_type
    return config_data

def is_filename_legal(filename:str) -> bool:
    if(len(filename) > current_app.config['MAX_FILENAME_LENGTH']):
        return False
    for letter in filename:
        if(letter in current_app.config['BANNED_CHARACTERS']):
            return False
    return True

def save_configs(configs:dict) -> None:
    config_data = {}
    with open('configurable_data.xml', 'rt', encoding = 'UTF-8') as file:
        parsed_file = BeautifulSoup(file, 'xml')
        for element in parsed_file.find_all('config'):
            config_name = element.find('name').text
            if(isinstance(configs[config_name], bytes)):
                config_data[config_name] = configs[config_name].decode()
            else:
                config_data[config_name] = configs[config_name]
    with open(os.path.join('instance', 'config.json'), 'wt', encoding='utf-8') as file:
        json.dump(config_data, file, indent = 1)

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
    conn = sqlite3.connect(os.path.join('instance', 'users.db'))
    cur = conn.cursor()
    no_of_files = cur.execute('''SELECT COUNT(*)
                                            FROM files INNER JOIN users ON users.UUID=files.UUID
                                            WHERE publicFilename=? AND username=?;''',
                                            (filename, username)).fetchone()[0]
    if(no_of_files > 0):
        conn.commit()
        cur.close()
        current_app.logger.info(f'{username} tried saving file with an existing filename: {filename}', {'log_type': 'file save'})
        return (False, "Couldn't save the file: file with such name already exists.")
    uploader_UUID = cur.execute('''SELECT UUID
                                                FROM users
                                                WHERE username=?;''',
                                                (username, )).fetchone()[0]
    internal_name = str(uuid.uuid4())
    file.save(os.path.join('files', uploader_UUID, internal_name))
    cur.execute('INSERT INTO files (publicFilename, internalFilename, UUID) VALUES (?, ?, ?);', (filename, internal_name, uploader_UUID))
    conn.commit()
    cur.close()
    conn.close()
    current_app.logger.info(f'{username} has saved a new file on the server: {filename}', {'log_type': 'file save'})
    return (True, 'File has been saved on the server.')

def share_file(filename:str, username:str) -> tuple[bool, str]:
    with sqlite3.connect(os.path.join('instance','users.db')) as conn:
        cur = conn.cursor()
        file_shared = bool(
                        cur.execute('''select count(*) from fileShares
                            left join files on files.internalFilename = fileShares.internalFilename
                            inner join users on files.UUID = users.UUID
                            where publicFilename=? and username=?;''', (filename, username)).fetchone()[0]
                        )
                        
                        
        if(file_shared):
            cur.close()
            current_app.logger.info(f'{username} has tried to share an already shared file: {filename}', {'log_type': 'file share'})
            return (False, 'Error: this file is already shared!')
        else:
            internal_filename = cur.execute('''SELECT internalFilename
                                                FROM files INNER JOIN users ON files.UUID = users.UUID
                                                WHERE publicFilename = ? AND username = ?;''', (filename, username)).fetchone()[0]
            share_url = str(uuid.uuid4())
            cur.execute('INSERT INTO fileShares VALUES (?, ?)', (internal_filename, share_url))
            cur.close()
            current_app.logger.info(f'{username} has shared a new file: {filename}', {'log_type': 'file share'})
            return (True, f'File shared! Share URL is: {request.url_root}shared_files/{share_url}')

def unshare_file(filename:str, username:str) -> tuple[bool, str]:
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        share_url = cur.execute('''SELECT shareURL
                                    FROM files INNER JOIN users INNER JOIN fileShares ON files.internalFilename=fileShares.internalFilename
                                    WHERE publicFilename=? AND username=?;''',
                                    (filename, username)).fetchone()
        if(share_url is not None):
            cur.execute('DELETE FROM fileShares WHERE shareURL = ?', (share_url[0], ))
            current_app.logger.info(f'{username} has stopped sharing {filename}', {'log_type': 'file share'})
            cur.close()
            conn.commit()
            return (True, 'File unshared.')