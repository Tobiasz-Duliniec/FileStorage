from flask import Flask, render_template, send_from_directory, request, abort
from werkzeug import utils
import os

app=Flask(__name__)

def get_file_list():
    pliki=tuple(x for x in os.listdir('files') if os.path.isfile(f'files/{x}'))
    return pliki

@app.route('/style.css')
def send_css():
    return send_from_directory('static', 'style.css')

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if(request.method=='POST'):
        file=request.files['file']
        filename=file.filename
        if(filename==''):
            return render_template('file_upload.html', status="You haven't attached any files!",saved=False)
        if(filename not in get_file_list()):
            file.save('files/'+utils.secure_filename(filename))
            return render_template('file_upload.html', status='file has been saved on the server.',saved=True)
        return render_template('file_upload.html', status='cannot save file - file with such name already exists.',saved=False)
    return render_template('file_upload.html')

@app.route('/download/<file>')
def send_file(file):
    if(os.path.isfile(f"files/{file}")):
        return send_from_directory('files', file, as_attachment=True)
    else:
        abort(404)

@app.route('/download')
def download():
    files=get_file_list()
    return render_template("file_download.html", files=files, number_of_files=len(files))

@app.route('/')
def index():
    return render_template("index.html")

if(__name__=="__main__"):
    app.run()
