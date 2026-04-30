'''
Database querying functions
'''
from classes.File import File
from flask import current_app
import os
import sqlite3


def add_account_to_database(username:str, password_hash:str, user_UUID:str, permissions:str) -> tuple[bool, str]:
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        try:
            cur.execute('INSERT INTO users(username, password, UUID, permissions) VALUES (?, ?, ?, ?)', (username, password_hash, user_UUID, permissions))
            cur.close()
            conn.commit()
            current_app.logger.info(f'New account has been created: {username}', {'log_type': 'account'})
            return (True, 'New account has been added to database')
        except sqlite3.IntegrityError as e:
            cur.close()
            current_app.logger.error(f'An error has occured while adding account {username} to database: {e}.', {'log_type': 'account'})
            return (False, e)

def add_file_to_database(public_filename:str, internal_filename:str, uploader_UUID:str):
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        cur.execute('INSERT INTO files (publicFilename, internalFilename, UUID) VALUES (?, ?, ?);', (public_filename, internal_filename, uploader_UUID))
        cur.close()
        conn.commit()

def add_share_to_database(internal_filename:str, share_url:str):
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        cur.execute('INSERT INTO fileShares VALUES (?, ?)', (internal_filename, share_url))
        cur.close()
        conn.commit()

def change_database_password(username:str, new_password:str) -> None:
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        cur.execute('''UPDATE users
                        SET password = ?
                        WHERE username = ?
                        ''',
                    (new_password, username))
        cur.close()
        conn.commit()

def create_initial_database_tables(admin_UUID:str, password:str) -> None:
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn: 
        cur = conn.cursor()
        cur.execute('''CREATE TABLE users (UUID TEXT PRIMARY KEY,
                                                                username TEXT NOT NULL UNIQUE,
                                                                password BLOB NOT NULL,
                                                                permissions INTEGER NOT NULL DEFAULT 0);''')
        cur.execute('INSERT INTO users (UUID, username, password, permissions) VALUES (?, "admin", ?, 1)', (admin_UUID, password))
        cur.execute('''CREATE TABLE files (internalFilename TEXT PRIMARY KEY,
                                                                publicFilename TEXT NOT NULL,
                                                                UUID TEXT NOT NULL,
                                                                FOREIGN KEY(UUID) REFERENCES users(UUID));
                                                                ''')
        cur.execute('''CREATE TABLE fileShares (internalFilename TEXT PRIMARY KEY,
                                                                shareURL TEXT UNIQUE,
                                                                FOREIGN KEY(internalFilename) REFERENCES files(internalFilename) ON DELETE CASCADE);''')
        conn.commit()
        cur.close()

def delete_file_from_database(public_filename:str, user_UUID:str) -> bool:
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        cur.execute('PRAGMA foreign_keys = ON;')
        cur.execute('DELETE FROM files WHERE publicFilename=? AND UUID=?', (public_filename, user_UUID))
        conn.commit()
    cur.close()

def delete_share(share_url:str):
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        cur.execute('DELETE FROM fileShares WHERE shareURL = ?', (share_url, ))
        conn.commit()
        cur.close()

def get_database_password(username:str) -> str:
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        password = cur.execute('''SELECT password
                                            FROM users
                                            WHERE username=?
                                            LIMIT 1;''',
                                  (username,)).fetchone()
        cur.close()
    return password

def get_file_count_by_user(username:str) -> int:
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        number_of_all_files = conn.execute('''SELECT count(*)
                                        FROM files
                                        INNER JOIN users ON files.UUID=users.UUID
                                        WHERE username=?;''', (username, )).fetchone()[0]
        cur.close()
    return number_of_all_files

def get_file_data_by_share_url(share_url:str) -> File|None:
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        file = cur.execute('''SELECT publicFilename, files.internalFilename, users.UUID, username, shareURL
                                            FROM fileShares
                                            INNER JOIN files
                                            ON fileShares.internalFilename = files.internalFilename
                                            INNER JOIN users
                                            ON files.UUID = users.UUID
                                            WHERE shareURL = ?;''',
                                        (share_url, )).fetchone()
    try:
        file = File(file[0], file[1], file[2], file[3], file[4])
    except TypeError:
        file = None
    return file

def get_file_data_by_filename(public_filename:str, username:str) -> File|None:
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        file = cur.execute('''SELECT publicFilename, files.internalfilename, users.UUID, username, shareURL
                                            FROM users
                                            INNER JOIN files
                                            ON users.UUID = files.UUID
                                            LEFT JOIN fileShares
                                            on fileShares.internalFilename = files.internalFilename
                                            WHERE publicFilename = ?
                                            AND username = ?''',
                                            (public_filename, username)).fetchone()
    try:
        file = File(file[0], file[1], file[2], file[3], file[4])
    except TypeError:
        file = None
    return file

def get_file_list(username:str, limit:int, offset:int) -> list:
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        file_list = cur.execute('''SELECT publicFilename, internalFilename
                                            FROM files INNER JOIN users ON files.UUID=users.UUID
                                            WHERE username=? LIMIT ? OFFSET ?;''',
                                (username, limit, offset)).fetchall()
        cur.close()
    return file_list
        
def get_internal_filename_by_username(public_filename:str, username:str) -> str:
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        internal_filename = cur.execute('''SELECT internalFilename
                                        FROM files INNER JOIN users ON files.UUID = users.UUID
                                        WHERE publicFilename=? AND username=? LIMIT 1;''', (public_filename, username)).fetchone()[0]
        cur.close()
    return internal_filename

def get_internal_filename_by_uuid(public_filename:str, user_UUID:str) -> str:
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        internal_filename = cur.execute('SELECT internalFilename FROM files WHERE publicFilename=? AND UUID=? LIMIT 1', (public_filename, user_UUID)).fetchone()[0]
        cur.close()
    return internal_filename

def get_share_url(public_filename:str, username:str) -> list:
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        share_url = cur.execute('''SELECT shareURL
                                    FROM files INNER JOIN users INNER JOIN fileShares ON files.internalFilename=fileShares.internalFilename
                                    WHERE publicFilename=? AND username=?;''',
                                    (public_filename, username)).fetchone()
    return share_url

def get_user_permissions(username:str) -> str:
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        permissions = cur.execute('''SELECT permissions
                            FROM users
                            WHERE username=?;''',
                            (username, )).fetchone()[0]
        cur.close()
    return permissions

def get_UUID_by_username(username:str) -> str:
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        user_UUID = cur.execute('SELECT UUID FROM users WHERE username=? LIMIT 1', (username, )).fetchone()[0]
        cur.close()
    return user_UUID

def test_for_public_filename(public_filename:str, username:str) -> bool:
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        no_of_files = cur.execute('''SELECT COUNT(*)
                                    FROM files INNER JOIN users ON users.UUID=files.UUID
                                    WHERE publicFilename=? AND username=?;''',
                                    (public_filename, username)).fetchone()[0]
        cur.close()
    return no_of_files > 0

def test_for_shared_file(public_filename:str, username:str) -> bool:
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        is_file_shared = bool(
            cur.execute('''select count(*) from fileShares
            left join files on files.internalFilename = fileShares.internalFilename
            inner join users on files.UUID = users.UUID
            where publicFilename=? and username=?;''', (public_filename, username)).fetchone()[0]
        )
        cur.close()
    return is_file_shared
