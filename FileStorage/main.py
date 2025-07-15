'''
Main file for the website.
'''

from flask import Flask, abort, flash, has_request_context, redirect, render_template, Response, request, send_from_directory, session, url_for
import bcrypt
import funcs
import json
import logging.config
import os
import sqlite3
import uuid

from admin import admin_panel
from errors import Errors


class ConsoleFormatter(logging.Formatter):
    def format(self, record):
        if has_request_context():
            record.ip = request.remote_addr
            record.username = session.get('username')
            record.method = request.method
            record.url = request.url
            record.status_code = request.status_code if hasattr(request, 'status_code') else None
            record.user_agent = request.user_agent
            record.log_type = record.args.get('log_type')
        else:
            record.ip = None
            record.username = None
            record.method = None
            record.url = None
            record.status_code = None
            record.user_agent = None
            record.log_type = 'start up process'
        return super().format(record)

class JSONLinesFormatter(logging.Formatter):
    def format(self, record):
        if has_request_context():
            username = session.get('username', None)
            record.ip = f'"{request.remote_addr}"'
            record.username = f'"{username}"' if username is not None else 'null'
            record.method = f'"{request.method}"'
            record.url = f'"{request.url}"'
            record.status_code = request.status_code if hasattr(request, 'status_code') else 'null'
            record.user_agent = f'"{request.user_agent}"'
            record.log_type = 'HTTP request'
        else:
            record.ip = 'null'
            record.username = 'null'
            record.method = 'null'
            record.url = 'null'
            record.status_code = 'null'
            record.user_agent = 'null'
            record.log_type = 'startup process'
        return super().format(record)

logging.config.dictConfig({
    'version': 1,
    'formatters': {
        'default': {
            '()': '__main__.ConsoleFormatter',
            'format': '%(levelname)s | Time: %(asctime)s | IP: %(ip)s | Username: %(username)s | Method: %(method)s | URL: %(url)s | Status code: %(status_code)s | User agent: %(user_agent)s | Log type: %(log_type)s | Message: %(message)s',
            'datefmt': '%Y-%d-%m %H:%M:%S'
        },
        'JSON_Lines': {
            '()': '__main__.JSONLinesFormatter',
            'format': '{"levelname": "%(levelname)s", "time": %(asctime)s, "ip": %(ip)s, "username": %(username)s, "method": %(method)s, "url": %(url)s, "status_code": %(status_code)s, "user_agent": %(user_agent)s, "log_type": "%(log_type)s", "message": "%(message)s"}',
            'datefmt': '"%Y-%d-%m %H:%M:%S"'
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'stream': 'ext://sys.stdout',
            'formatter': 'default'
        },
        'JSON_Lines_file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'JSON_Lines',
            'filename': 'logs.jsonl',
            'encoding': 'UTF-8',
            'maxBytes': 10 * 1024 * 1024 * 1024,
            'backupCount': 10
        }
    },
    'root': {
        'handlers': ('console', 'JSON_Lines_file'),
        'level': 'INFO'
    }
})

app = Flask(__name__)
app.register_blueprint(admin_panel)
app.register_blueprint(Errors)
logging.getLogger('werkzeug').disabled = True

@app.after_request
def http_request_logger(response):
    request.status_code = response.status_code
    request.user_agent = request.headers.get('User-Agent')
    app.logger.info('A HTTP finished processing.', {'log_type': 'HTTP request'})
    return response

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
    app.logger.info('Creating users database.')
    password = bcrypt.hashpw('admin'.encode('utf-8'), app.config['GENSALT'])
    admin_UUID = str(uuid.uuid4())
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn: 
        cur = conn.cursor()
        cur.execute('''CREATE TABLE users (UUID TEXT PRIMARY KEY,
                                                                username TEXT NOT NULL UNIQUE,
                                                                password BLOB NOT NULL,
                                                                permissions INTEGER NOT NULL DEFAULT 0);''')
        cur.execute('INSERT INTO users (UUID, username, password, permissions) VALUES (?, "admin", ?, 1)', (admin_UUID, password))
        cur.execute('''CREATE TABLE files (internalFilename TEXT PRIMARY KEY,
                                                                publicFilename TEXT NOT NULL,
                                                                UUID TEXT NOT NULL UNIQUE,
                                                                FOREIGN KEY(UUID) REFERENCES users(UUID));
                                                                ''')
        cur.execute('''CREATE TABLE fileShares (internalFilename TEXT PRIMARY KEY,
                                                                shareURL TEXT UNIQUE,
                                                                FOREIGN KEY(internalFilename) REFERENCES files(internalFilename) ON DELETE CASCADE);''')

        conn.commit()
        cur.close()
    admin_file_folder = os.path.join('files', admin_UUID)
    if(not os.path.isdir(admin_file_folder)):
        os.makedirs(admin_file_folder)
    app.logger.info('Users database created.')

def check_databases() -> None:
    app.logger.info('Checking database.')
    if(not os.path.isfile(os.path.join('instance', 'users.db'))):
        create_users_database()
    else:
        app.logger.info('Database found.')

def set_configs() -> None:
    '''
    Loads data from config file if it exists.
    If it doesn't, it generates one.
    '''
    app.logger.info('Checking config settings.')
    if(os.path.isfile(os.path.join('instance', 'config.json'))):
        app.logger.info('Config file found. Importing.')
        app.config.from_file(os.path.join('instance', 'config.json'), load = json.load)
        app.config['GENSALT'] = app.config['GENSALT'].encode('utf-8')
        app.config['SECRET_KEY'] = app.config['SECRET_KEY'].encode('utf-8')
    else:
        app.logger.info('Config file not found: using default config settings.')
        app.config['BANNED_CHARACTERS'] = ['<', '>', '"', "'",  '\\', '/', ':', '|', '?', '*', '#']
        app.config['GENSALT'] = bcrypt.gensalt()
        app.config['MAX_FILE_SIZE_GB'] = 1
        app.config['MAX_FILES_PER_PAGE'] = 30
        app.config['MAX_FILENAME_LENGTH'] = 32
        app.config['PERMANENT_SESSION_LIFETIME'] = 10800
        app.config['SECRET_KEY'] = bcrypt.gensalt()
        app.config['SEND_ROBOTS_TXT'] = False
        app.config['SESSION_COOKIE_HTTPONLY'] = True
        app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
        app.config['SESSION_COOKIE_SECURE'] = False
        funcs.save_configs(app.config)
    app.config['MAX_CONTENT_LENGTH'] = app.config['MAX_FILE_SIZE_GB'] * 1024 * 1024 * 1024
    app.logger.info('Config settings set up.')

def convert_bytes_to_megabytes(size:int) -> float:
    return round((size / (1024 * 1024)), 3)

def get_file_list(username:str, file_start:int) -> dict:
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        user_UUID = cur.execute('SELECT UUID FROM users WHERE username=?;', (username, )).fetchone()[0]
        file_list = cur.execute('''SELECT publicFilename, internalFilename
                                            FROM files INNER JOIN users ON files.UUID=users.UUID
                                            WHERE username=? LIMIT ? OFFSET ?;''',
                                (username,
                                 app.config['MAX_FILES_PER_PAGE'],
                                file_start)).fetchall()
        file_list = dict(
            (file[0], convert_bytes_to_megabytes(os.path.getsize(os.path.join('files', user_UUID, file[1]))))
                     for file in file_list)
        cur.close()
    return file_list

@app.route('/favicon.ico')
def send_favicon():
    return send_from_directory('static', 'favicon.ico')

@app.route('/style.css')
def send_css():
    return send_from_directory('static', 'style.css')

@app.route('/robots.txt')
def send_robots_txt():
    if(app.config['SEND_ROBOTS_TXT']):
        return send_from_directory('static', 'robots.txt')
    else:
        abort(404)

@app.route('/upload', methods = ['GET', 'POST'])
def upload_file_page():
    if(not session.get('username')):
        abort(401)
    if(request.method == 'POST'):
        username = session.get('username')
        file = request.files['file']
        filename = file.filename
        if(filename == ''):
            app.logger.info(f"{username} tried saving file but didn't send any.", {'log_type': 'file save'})
            flash('Failed to save the file: no file found.', 'error')
            return render_template('file_upload.html')
        if(not is_filename_legal(filename)):
            app.logger.info(f'{username} tried saving file with an invalid filename: {filename}', {'log_type': 'file save'})
            flash('Invalid filename: filename contains illegal characters or is too long.', 'error')
            return render_template('file_upload.html')
        conn = sqlite3.connect(os.path.join('instance', 'users.db'))
        cur = conn.cursor()
        no_of_files = cur.execute('''SELECT COUNT(*)
                                            FROM files INNER JOIN users ON users.UUID=files.UUID
                                            WHERE publicFilename=? AND username=?;''',
                                            (filename, username)).fetchone()[0]
        if(no_of_files > 0):
            conn.commit()
            cur.close()
            app.logger.info(f'{username} tried saving file with an existing filename: {filename}', {'log_type': 'file save'})
            flash("Couldn't save the file: file with such name already exists", 'error')
            return render_template('file_upload.html')
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
        app.logger.info(f'{username} has saved a new file on the server: {filename}', {'log_type': 'file save'})
        flash('File has been saved on the server.', 'success')
        return render_template('file_upload.html')
    return render_template('file_upload.html')

@app.route('/unshare/<file>', methods = ['POST'])
def unshare_file(file:str):
    if(not session.get('username')):
        abort(401)
    username = session.get('username')
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        share_url = cur.execute('''SELECT shareURL
                                    FROM files INNER JOIN users INNER JOIN fileShares ON files.internalFilename=fileShares.internalFilename
                                    WHERE publicFilename=? AND username=?;''',
                                    (file, username)).fetchone()
        if(share_url is not None):
            cur.execute('DELETE FROM fileShares WHERE shareURL = ?', (share_url[0], ))
            app.logger.info(f'{username} has stopped sharing {file}', {'log_type': 'file share'})
            flash('File unshared.', 'success')
        cur.close()
    return redirect(url_for('show_file_info', file = file))

@app.route('/account', methods = ['GET', 'POST'])
def account_info():
    if(not session.get('username')):
        abort(401)
    username = session.get('username')
    if(request.method == 'POST'):
        new_password = request.form.get('new_password', None)
        new_password_confirmation = request.form.get('new_password_confirmation', None)
        current_password = request.form.get('current_password', None)
        if(current_password is not None and new_password is not None and new_password_confirmation is not None and new_password == new_password_confirmation):
            new_password = bcrypt.hashpw(new_password.encode('utf-8'), app.config['GENSALT'])
            current_password = bcrypt.hashpw(current_password.encode('utf-8'), app.config['GENSALT'])
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
                    flash('Password changed succesfully.', 'success')
                    app.logger.info(f'{username} has changed their password.', {'log_type': 'account'})
                else:
                    flash('Please input the correct current password', 'error')
                    app.logger.info('Password change fail: incorrect current password.', {'log_type': 'account'})
                cur.close()
                conn.commit()
        else:
            flash('Please enter two matching passwords and your current password.', 'error')
            app.logger.info('Password change fail: incorrect or no account data provided.', {'log_type': 'account'})
    return render_template('account.html', username = username)


@app.route('/delete/<file>', methods = ['POST'])
def delete_file(file:str):
    if(not session.get('username')):
        abort(401)
    username = session.get('username')
    if(request.method == 'POST'):
        with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
            cur = conn.cursor()
            cur.execute('PRAGMA foreign_keys = ON;')
            user_UUID = cur.execute('SELECT UUID FROM users WHERE username=? LIMIT 1', (username, )).fetchone()[0]
            internal_filename = cur.execute('SELECT internalFilename FROM files WHERE publicFilename=? AND UUID=? LIMIT 1', (file, user_UUID)).fetchone()[0]
            cur.execute('DELETE FROM files WHERE publicFilename=? AND UUID=?', (file, user_UUID))
            conn.commit()
            cur.close()
        os.remove(f'files/{user_UUID}/{internal_filename}')
        app.logger.info(f'{username} has deleted a file: {file}', {'log_type': 'file deletion'})
        flash('File deleted succesfully', 'success')
    return redirect(url_for('download_file_page'))

@app.route('/share/<file>', methods = ['POST'])
def share_file(file):
    if(not session.get('username')):
        abort(401)
    username = session.get('username')
    with sqlite3.connect(os.path.join('instance','users.db')) as conn:
        cur = conn.cursor()
        file_shared = bool(
                                cur.execute('''select count(*) from files
                                                inner join users on files.UUID = users.UUID
                                                where publicFilename=? and username=?;''', (file, username)).fetchone()[0]
                        )
        if(file_shared):
            flash('Error: this file is already shared!', 'error')
            app.logger.info(f'{username} has tried to share an already shared file: {file}', {'log_type': 'file share'})
        else:
            internal_filename = cur.execute('''SELECT internalFilename
                                                FROM files INNER JOIN users ON files.UUID = users.UUID
                                                WHERE publicFilename = ? AND username = ?;''', (file, username)).fetchone()[0]
            share_url = str(uuid.uuid4())
            cur.execute('INSERT INTO fileShares VALUES (?, ?)', (internal_filename, share_url))
            app.logger.info(f'{username} has shared a new file: {file}', {'log_type': 'file share'})
            flash(f'File shared! Share URL is: {request.url_root}shared_files/{share_url}', 'success')
        cur.close()
    return redirect(url_for('show_file_info', file = file))

@app.route('/download/<file>')
@app.route('/shared_file_download/<file>')
def send_file(file:str):
    if(not session.get('username')):
        return redirect('/login')
    username = session.get('username')
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        try:
            if(request.path.startswith('/download/')):
                internal_filename, publicFilename, user_UUID = cur.execute('''SELECT internalfilename, publicFilename, users.UUID
                                                                FROM users
                                                                INNER JOIN files
                                                                ON users.UUID = files.UUID
                                                                WHERE publicFilename = ?
                                                                AND username = ?;''',
                                                        (file, username)).fetchone()
            else:
                internal_filename, publicFilename, user_UUID = cur.execute('''SELECT files.internalFilename, publicFilename, UUID
                                                                FROM fileShares
                                                                INNER JOIN files
                                                                ON fileShares.internalFilename = files.internalFilename
                                                                INNER JOIN users
                                                                ON files.UUID = users.UUID
                                                                WHERE shareURL = ?;''',
                                                        (file, )).fetchone()
            cur.close()
        except TypeError:
            abort(404)
    
    if(os.path.isfile(os.path.join('files', user_UUID, internal_filename))):
        app.logger.info(f'{username} downloaded a file: {file}', {'log_type': 'file download'})
        return send_from_directory(os.path.join('files', user_UUID), internal_filename, download_name = publicFilename, as_attachment = True)
    else:
        abort(404)

@app.route('/shared_files/<shareURL>')
def show_shared_file_info(shareURL:str):
    if(not session.get('username')):
        abort(404)
    username = session.get('username')
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        user_UUID = cur.execute('SELECT UUID FROM users WHERE username=?;', (username, )).fetchone()[0]
        file_info = cur.execute('''SELECT publicFilename, files.internalFilename, username
                                        FROM files INNER JOIN users ON files.UUID=users.UUID
                                        INNER JOIN fileShares ON files.internalFilename=fileShares.internalFilename
                                        WHERE shareURL=?;''', (shareURL, )).fetchone()
        cur.close()
        if(file_info is None):
            abort(404)
        file_info = file_info + (convert_bytes_to_megabytes(os.path.getsize(os.path.join('files', user_UUID, file_info[1]))), shareURL)
    return render_template('files.html', file = file_info)

@app.route('/files/<file>')
def show_file_info(file:str):
    if(not session.get('username')):
        abort(404)
    username = session.get('username')
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        user_UUID = cur.execute('SELECT UUID FROM users WHERE username=?;', (username, )).fetchone()[0]
        file = cur.execute('''SELECT publicFilename, files.internalFilename, shareURL
                                        FROM files
                                        INNER JOIN users ON files.UUID=users.UUID
                                        LEFT JOIN fileShares ON files.internalFilename=fileShares.internalFilename
                                        WHERE publicFilename=? and username=?''',
                           (file, username)).fetchone()
        cur.close()
        file_info = (file[0], convert_bytes_to_megabytes(os.path.getsize(os.path.join('files', user_UUID, file[1]))), file[2])
    return render_template('files.html', file = file_info)

@app.route('/download')
def download_file_page():
    if(not session.get('username')):
        abort(401)
    username = session.get('username')
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        number_of_all_files = conn.execute('''SELECT count(*)
                                                    FROM files
                                                    INNER JOIN users ON files.UUID=users.UUID
                                                    WHERE username=?;''', (username, )).fetchone()[0]
    try:
        file_start = int(request.args.get('start', 0))
    except ValueError:
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
        conn = sqlite3.connect(os.path.join('instance', 'users.db'))
        cur = conn.cursor()
        user = cur.execute('''SELECT username
                                        FROM users
                                        WHERE username=?
                                        AND password=?;''',
                              (username, password)).fetchone()
        if(user is None):
            app.logger.info(f'Failed log in attempt as {username}.', {'log_type': 'log in attempt'})
            return render_template('login.html', success = False)
        cur.close()
        conn.close()
        session.permanent = True
        session['username'] = username
        app.logger.info(f'Succesful log in attempt as {username}.', {'log_type': 'log in attempt'})
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
    app.logger.info('Starting website.')
    if(not os.path.isdir('instance')):
        app.logger.info('Instance folder not found. Creating.')
        os.mkdir('instance')
    set_configs()
    check_databases()
    app.run(host='0.0.0.0')

if(__name__ == '__main__'):
    start_website()
