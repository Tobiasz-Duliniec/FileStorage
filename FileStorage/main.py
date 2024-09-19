from flask import Flask, render_template, send_from_directory, request, abort, session, redirect
from werkzeug import utils
import os
import sqlite3

app = Flask(__name__)
app.config['MAX_FILE_SIZE_GB'] = 1
app.config['MAX_CONTENT_LENGTH'] = app.config['MAX_FILE_SIZE_GB'] * 1024 * 1024 * 1024

app.secret_key = 'secret_key'
# remember to change the secret key to something more secure
# when putting the site to production

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

if(__name__ == '__main__'):
    app.run()
