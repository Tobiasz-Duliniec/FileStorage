'''
Main file for the website.
'''

from flask import Flask, abort, flash, has_request_context, redirect, render_template, Response, request, send_from_directory, session, url_for
import bcrypt
import funcs.funcs as funcs
import funcs.config as config_funcs
import json
import logging.config
import os
import sqlite3
import uuid


class ConsoleFormatter(logging.Formatter):
    def format(self, record):
        if(has_request_context()):
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
        if(has_request_context()):
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
logging.getLogger('werkzeug').disabled = True

@app.after_request
def http_request_logger(response):
    request.status_code = response.status_code
    request.user_agent = request.headers.get('User-Agent')
    app.logger.info('A HTTP finished processing.', {'log_type': 'HTTP request'})
    return response

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
    file_upload_form = forms.FileUploadForm()
    if(file_upload_form.validate_on_submit()):
        username = session.get('username')
        file = file_upload_form.data['file']
        status = funcs.save_file(file, username)
        flash(status[1], 'success' if status[0] else 'error')
    return render_template('file_upload.html', file_upload_form = file_upload_form)

@app.route('/unshare/<file>', methods = ['POST'])
def unshare_file(file:str):
    if(not session.get('username')):
        abort(401)
    username = session.get('username')
    status = funcs.unshare_file(file, username)
    flash(status[1], 'success' if status[0] else 'error')
    return redirect(url_for('show_file_info', file = file))

@app.route('/account', methods = ['GET', 'POST'])
def account_info():
    if(not session.get('username')):
        abort(401)
    username = session.get('username')
    password_reset_form = forms.PasswordResetForm()
    if(password_reset_form.is_submitted()):
        current_password = password_reset_form.current_password.data
        new_password = password_reset_form.new_password.data
        new_password_confirmation = password_reset_form.confirm_password.data
        status = funcs.change_password(new_password, new_password_confirmation, current_password, username)
        flash(status[1], 'success' if status[0] else 'error')
    return render_template('account.html', username = username, password_reset_form = password_reset_form)

@app.route('/delete/<file>', methods = ['POST'])
def delete_file(file:str):
    if(not session.get('username')):
        abort(401)
    username = session.get('username')
    if(request.method == 'POST'):
        status = funcs.delete_file(file, username)
        flash(status[1], 'success' if status[0] else 'error')
    return redirect(url_for('download_file_page'))

@app.route('/share/<file>', methods = ['POST'])
def share_file(file):
    if(not session.get('username')):
        abort(401)
    username = session.get('username')
    status = funcs.share_file(file, username)
    flash(status[1], 'success' if status[0] else 'error')
    return redirect(url_for('show_file_info', file = file))

@app.route('/download/<file>', methods = ['GET', 'POST'])
@app.route('/shared_file_download/<file>', methods = ['GET', 'POST'])
def send_file(file:str):
    if(not session.get('username')):
        return redirect('/login')
    username = session.get('username')
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        try:
            if(request.path.startswith('/download/')):
                internal_filename, public_filename, user_UUID = cur.execute('''SELECT internalfilename, publicFilename, users.UUID
                                                                FROM users
                                                                INNER JOIN files
                                                                ON users.UUID = files.UUID
                                                                WHERE publicFilename = ?
                                                                AND username = ?;''',
                                                        (file, username)).fetchone()
            else:
                internal_filename, public_filename, user_UUID = cur.execute('''SELECT files.internalFilename, publicFilename, users.UUID
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
        return send_from_directory(os.path.join('files', user_UUID), internal_filename, download_name = public_filename, as_attachment = True)
    else:
        abort(404)

@app.route('/shared_files/<shareURL>')
def show_shared_file_info(shareURL:str):
    if(not session.get('username')):
        abort(404)
    username = session.get('username')
    file_download_form = forms.FileDownloadForm()
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        user_UUID = cur.execute('''SELECT users.UUID
                                FROM fileShares INNER JOIN files on fileShares.internalFilename = files.internalFilename
                                INNER JOIN users ON files.UUID = users.UUID
                                WHERE shareURL=?;''', (shareURL, )).fetchone()[0]
        file_info = cur.execute('''SELECT publicFilename, files.internalFilename, username
                                FROM files INNER JOIN users ON files.UUID=users.UUID
                                INNER JOIN fileShares ON files.internalFilename=fileShares.internalFilename
                                WHERE shareURL=?;''', (shareURL, )).fetchone()
        cur.close()
        if(file_info is None):
            abort(404)
        file_info = file_info + (funcs.convert_bytes_to_megabytes(os.path.getsize(os.path.join('files', user_UUID, file_info[1]))), shareURL)
    return render_template('files.html', file = file_info, file_download_form = file_download_form)

@app.route('/files/<file>')
def show_file_info(file:str):
    if(not session.get('username')):
        abort(404)
    username = session.get('username')
    file_download_form = forms.FileDownloadForm()
    file_delete_form = forms.FileDeleteForm()
    file_share_form = forms.FileShareForm()
    file_unshare_form = forms.FileUnshareForm()
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
        file_info = (file[0], funcs.convert_bytes_to_megabytes(os.path.getsize(os.path.join('files', user_UUID, file[1]))), file[2])
    return render_template('files.html', file = file_info, file_download_form = file_download_form, file_delete_form = file_delete_form,
                                                                   file_share_form = file_share_form, file_unshare_form = file_unshare_form)

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
    files = funcs.get_file_list(username, file_start)
    return render_template("file_download.html", files = files, number_of_files = len(files), number_of_all_files = number_of_all_files)

@app.route('/login', methods = ['GET', 'POST'])
def login():
    if(session.get('username')):
        return redirect('/')
    login_form = forms.LoginForm()
    if(login_form.validate_on_submit()):
        username = login_form.username.data
        password = login_form.password.data
        status = funcs.validate_login_data(username, password)
        if(not status):
            return render_template('login.html', login_form = login_form, success = False), 400
        session.permanent = True
        session['username'] = username
        return redirect('/')
    return render_template('login.html', login_form = login_form)

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
    with app.app_context():
        config_funcs.set_configurable_data()
        global forms
        import forms
        from admin import admin_panel
        from errors import Errors
        app.register_blueprint(admin_panel)
        app.register_blueprint(Errors)
        funcs.check_database()
    app.run(host='0.0.0.0')

if(__name__ == '__main__'):
    start_website()