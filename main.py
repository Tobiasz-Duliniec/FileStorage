'''
Main file for the website.
'''

from flask import Flask, abort, flash, redirect, render_template, request, send_from_directory, session
import bcrypt
import json
import os
import sqlite3
import uuid

from admin import admin_panel
from errors import Errors

app = Flask(__name__)
app.register_blueprint(admin_panel)
app.register_blueprint(Errors)

app.config['BANNED_CHARACTERS'] = {'<', '>', '"', "'",  '\\', '/', ':', '|', '?', '*', '#'}


def is_filename_legal(filename:str) -> bool:
    if(len(filename) > app.config['MAX_FILENAME_LENGTH']):
        return False
    for letter in filename:
        if(letter in app.config['BANNED_CHARACTERS']):
            return False
    return True

def create_users_database() -> None:
    '''
    Creates users database if it wasn't found during startup.
    The users database will contain only admin account with the password and username "admin".
    It is recommended that the password is changed before putting the site to production.
    '''
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    cur.execute('''CREATE TABLE users (userID INTEGER PRIMARY KEY AUTOINCREMENT,
                                                                username TEXT NOT NULL UNIQUE,
                                                                password BLOB NOT NULL,
                                                                UUID TEXT NOT NULL UNIQUE,
                                                                permissions INTEGER NOT NULL DEFAULT 0);
                        ''')
    password = bcrypt.hashpw('admin'.encode('utf-8'), app.config['GENSALT'])
    admin_UUID = str(uuid.uuid4())
    cur.execute('INSERT INTO users (username, password, UUID, permissions) VALUES ("admin", ?, ?, 1)', (password, admin_UUID))
    cur.execute('''CREATE TABLE files (fileID INTEGER PRIMARY KEY AUTOINCREMENT,
                                                            publicFilename TEXT NOT NULL,
                                                            internalFilename TEXT NOT NULL UNIQUE,
                                                            userID INTEGER NOT NULL,
                                                            FOREIGN KEY(userID) REFERENCES users(userID));
                        ''')
    conn.commit()
    cur.close()
    conn.close()
    admin_file_folder = os.path.join('files', admin_UUID)
    if(not os.path.isdir(admin_file_folder)):
        os.makedirs(admin_file_folder)

def check_databases() -> None:
    if(not os.path.isfile('users.db')):
        create_users_database()

def set_configs() -> None:
    '''
    Loads data from config file if it exists.
    If it doesn't, it generates one.
    '''
    if(os.path.isfile('config.json')):
        app.config.from_file('config.json', load = json.load)
        app.config['GENSALT'] = app.config['GENSALT'].encode('utf-8')
        app.config['SECRET_KEY'] = app.config['SECRET_KEY'].encode('utf-8')
    else:
        app.config['GENSALT'] = bcrypt.gensalt()
        app.config['MAX_FILE_SIZE_GB'] = 1
        app.config['MAX_FILES_PER_PAGE'] = 30
        app.config['MAX_FILENAME_LENGTH'] = 32
        app.config['PERMANENT_SESSION_LIFETIME'] = 10800
        app.config['SECRET_KEY'] = bcrypt.gensalt()
        app.config['SESSION_COOKIE_HTTPONLY'] = True
        app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
        config_data = {
            'GENSALT': app.config['GENSALT'].decode(),
            'MAX_FILE_SIZE_GB': app.config['MAX_FILE_SIZE_GB'],
            'MAX_FILES_PER_PAGE': app.config['MAX_FILES_PER_PAGE'],
            'MAX_FILENAME_LENGTH': app.config['MAX_FILENAME_LENGTH'],
            'PERMANENT_SESSION_LIFETIME': app.config['PERMANENT_SESSION_LIFETIME'],
            'SECRET_KEY': app.config['SECRET_KEY'].decode(),
            'SESSION_COOKIE_HTTPONLY': app.config['SESSION_COOKIE_HTTPONLY'],
            'SESSION_COOKIE_SAMESITE': app.config['SESSION_COOKIE_SAMESITE']
            }
        with open('config.json', 'wt') as file:
            json.dump(config_data, file, indent = 1)
    app.config['MAX_CONTENT_LENGTH'] = app.config['MAX_FILE_SIZE_GB'] * 1024 * 1024 * 1024

def convert_bytes_to_megabytes(size:int) -> float:
    size_in_megabytes = round((size / (1024 * 1024)), 3)
    return size_in_megabytes

def get_file_list(username:str, file_start:int) -> dict:
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    user_UUID = cur.execute('SELECT UUID FROM users WHERE username=?;', (username, )).fetchone()[0]
    file_list = cur.execute('''SELECT publicFilename, internalFilename
                                        FROM files INNER JOIN users ON files.userID=users.userID
                                        WHERE username=? LIMIT ? OFFSET ?;''',
                            (username,
                             app.config['MAX_FILES_PER_PAGE'],
                            file_start)
                            ).fetchall()
    file_list = dict(
        (file[0], convert_bytes_to_megabytes(os.path.getsize(os.path.join('files', user_UUID, file[1]))))
                 for file in file_list)
    cur.close()
    conn.close()
    return file_list

@app.route('/favicon.ico')
def send_favicon():
    return send_from_directory('static', 'favicon.ico')

@app.route('/style.css')
def send_css():
    return send_from_directory('static', 'style.css')

@app.route('/robots.txt')
def send_robots_txt():
    return send_from_directory('static', 'robots.txt')

@app.route('/upload', methods = ['GET', 'POST'])
def upload_file_page():
    if(not session.get('username')):
        abort(401)
    if(request.method == 'POST'):
        username = session.get('username')
        file = request.files['file']
        filename = file.filename
        if(filename == ''):
            flash('Failed to save the file: no file found.', 'error')
            return render_template('file_upload.html')
        if(not is_filename_legal(filename)):
            flash('Invalid filename: filename contains illegal characters or is too long.', 'error')
            return render_template('file_upload.html')
        conn = sqlite3.connect('users.db')
        cur = conn.cursor()
        no_of_files = cur.execute('''SELECT COUNT(*)
                                            FROM files INNER JOIN users ON users.userID=files.userID
                                            WHERE publicFilename=? AND username=?;''',
                                            (filename, username)).fetchone()[0]
        if(no_of_files > 0):
            conn.commit()
            cur.close()
            flash("Couldn't save the file: file with such name already exists", 'error')
            return render_template('file_upload.html')
        uploader_id, uploader_UUID = cur.execute('''SELECT userID, UUID
                                                                            FROM users
                                                                            WHERE username=?;''',
                                                        (username, )).fetchone()
        internal_name = str(uuid.uuid4())
        file.save(os.path.join('files', uploader_UUID, internal_name))
        cur.execute('INSERT INTO files (publicFilename, internalFilename, userID) VALUES (?, ?, ?);', (filename, internal_name, uploader_id))
        conn.commit()
        cur.close()
        conn.close()
        flash('File has been saved on the server.', 'success')
        return render_template('file_upload.html')
    return render_template('file_upload.html')

@app.route('/download/<file>')
def send_file(file):
    if(not session.get('username')):
        return redirect('/login')
    username = session.get('username')
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    internal_filename, user_UUID = cur.execute('''SELECT internalfilename, UUID
                                                    FROM users
                                                    INNER JOIN files
                                                    ON users.userID=files.userID
                                                    WHERE publicFilename=?
                                                    AND username=?;''',
                                            (file, username)).fetchone()
    cur.close()
    conn.close()
    if(os.path.isfile(os.path.join('files', user_UUID, internal_filename))):
        return send_from_directory(os.path.join('files', user_UUID), internal_filename, download_name = file, as_attachment = True)
    else:
        abort(404)

@app.route('/download')
def download_file_page():
    if(not session.get('username')):
        abort(401)
    username = session.get('username')
    with sqlite3.connect('users.db') as conn:
        number_of_all_files = conn.execute('''SELECT count(*)
                                                    FROM files
                                                    INNER JOIN users ON files.userID=users.userID
                                                    WHERE username=?''', (username, )).fetchone()[0]
    if(request.args.get('start') is not None):
        try:
            file_start = int(request.args.get('start'))
            if(file_start < 0):
                file_start = 0
        except ValueError:
            file_start = 0
    else:
        file_start = 0
    files = get_file_list(username, file_start)
    return render_template("file_download.html", files = files, number_of_files = len(files), number_of_all_files = number_of_all_files)

@app.route('/login', methods = ['GET', 'POST'])
def login():
    if(session.get('username')):
        return redirect('/')
    if(request.method == 'POST'):
        username = request.form.get('username')
        password = request.form.get('password')
        password = bcrypt.hashpw(password.encode('utf-8'), app.config['GENSALT'])
        conn = sqlite3.connect('users.db')
        cur = conn.cursor()
        user = cur.execute('''SELECT username
                                        FROM users
                                        WHERE username=?
                                        AND password=?;''',
                              (username, password)).fetchone()
        if(user is None):
            return render_template('login.html', success = False)
        cur.close()
        conn.close()
        session.permanent = True
        session['username'] = username
        return redirect('/')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/')

@app.route('/')
def index():
    return render_template('index.html')

def start_website():
    set_configs()
    check_databases()
    app.run()

if(__name__ == '__main__'):
    start_website()