from flask import Flask, render_template, send_from_directory, request, abort, session, redirect
from werkzeug import utils
import bcrypt
import json
import os
import sqlite3

app = Flask(__name__)

def create_users_database():
    '''
    The users database will contain only admin account with the password and username "admin".
    It is recommended that the password is changed before putting the site to production.
    '''
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    cur.execute('''CREATE TABLE users (userID INTEGER PRIMARY KEY AUTOINCREMENT,
                                                                username TEXT,
                                                                password BLOB,
                                                                permissions INTEGER)''')
    password = bcrypt.hashpw(bytes('admin'.encode('utf-8')), app.config['GENSALT'])
    cur.execute('INSERT INTO users (username, password, permissions) VALUES ("admin", ?, 1)', (password,))
    conn.commit()
    cur.close()
    conn.close()

def check_databases():
    '''
    If there are no required database files, the function creates them.
    '''
    if(not os.path.isfile('users.db')):
        create_users_database()

def set_configs():
    '''
    Loads data from config files.
    It is recommended that you change default values
    that contain sensitive data (gensalt, secret key)
    before putting the site to production
    since they are publicly available in the GitHub repo.
    '''
    app.config.from_file('config.json', load = json.load)
    app.config['GENSALT'] = bytes(app.config['GENSALT'].encode('utf-8'))
    app.config['MAX_CONTENT_LENGTH'] = app.config['MAX_FILE_SIZE_GB'] * 1024 * 1024 * 1024

def convert_bytes_to_megabytes(size:int) -> float:
    size_in_megabytes = round((size / (1024 * 1024)), 3)
    return size_in_megabytes

def get_file_list() -> dict:
    files = dict(
        (file, convert_bytes_to_megabytes(os.path.getsize(f'files/{file}')))
        for file in os.listdir('files')
        if os.path.isfile(f'files/{file}')
        )
    return files

@app.errorhandler(500)
def internal_server_error(e):
    msg = "Internal Server Error: something went wrong when processing your request."
    return render_template('error.html', msg = msg), 500

@app.errorhandler(413)
def request_entity_too_large(e):
    plural = 's' if app.config['MAX_FILE_SIZE_GB'] != 1 else ''
    msg = f"Requested Entity Too Large: you cannot upload files larger than {app.config['MAX_FILE_SIZE_GB']} gigabyte{plural}."
    return render_template('file_upload.html', status = msg, saved = False), 413

@app.errorhandler(404)
def page_not_found(e):
    msg = "Page Not Found: requested page couldn't be found."
    return render_template('error.html', msg = msg), 404

@app.errorhandler(401)
def unauthorized(e):
    msg = "Unauthorized: you need to log in to view this page."
    return render_template('error.html', msg = msg), 401

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
        file = request.files['file']
        filename = utils.secure_filename(file.filename)
        if(filename == ''):
            return render_template('file_upload.html', status = 'Failed to save the file: are you sure you have attached one?', saved = False)
        elif(filename not in get_file_list()):
            file.save('files/' + filename)
            return render_template('file_upload.html', status = 'File has been saved on the server.', saved = True)
        return render_template('file_upload.html', status = "Couldn't save the file: file with such name already exists.", saved = False)
    return render_template('file_upload.html')

@app.route('/download/<file>')
def send_file(file):
    if(not session.get('username')):
        return redirect('/login')
    file = utils.secure_filename(file)
    if(os.path.isfile(f"files/{file}")):
        return send_from_directory('files', file, as_attachment = True)
    else:
        abort(404)

@app.route('/download')
def download_file_page():
    if(not session.get('username')):
        abort(401)
    files = get_file_list()
    return render_template("file_download.html", files = files, number_of_files = len(files))

@app.route('/login', methods = ['GET', 'POST'])
def login():
    if(session.get('username')):
        return redirect('/')
    if(request.method == 'POST'):
        username = request.form.get('username')
        password = request.form.get('password')
        password = bcrypt.hashpw(bytes(username.encode('utf-8')), app.config['GENSALT'])
        conn = sqlite3.connect('users.db')
        cur = conn.cursor()
        results = cur.execute('SELECT username FROM users WHERE username=? AND password=? LIMIT 1', (username, password))
        username_list = results.fetchall()
        if(len(username_list) == 0):
            return render_template('login.html', success = False)
        username = username_list[0][0]
        cur.close()
        conn.close()
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

if(__name__ == "__main__"):
    start_website()
