from flask import Blueprint, abort, current_app, flash, has_request_context, redirect, render_template, Response, request, send_from_directory, session, url_for
import classes.forms as forms
import funcs.admin as admin_funcs
import funcs.config as config_funcs
import funcs.database as database_funcs
import funcs.funcs as funcs
import json
import os
import uuid


router = Blueprint('router', __name__)

@router.after_request
def http_request_logger(response):
    request.status_code = response.status_code
    request.user_agent = request.headers.get('User-Agent')
    current_app.logger.info('A HTTP finished processing.', {'log_type': 'HTTP request'})
    return response

@router.route('/favicon.ico')
def send_favicon():
    return send_from_directory('static', 'favicon.ico')

@router.route('/style.css')
def send_css():
    return send_from_directory('static', 'style.css', mimetype='text/css')

@router.route('/robots.txt')
def send_robots_txt():
    if(current_app.config['SEND_ROBOTS_TXT']):
        return send_from_directory('static', 'robots.txt')
    else:
        abort(404)

@router.route('/upload', methods = ['GET', 'POST'])
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

@router.route('/unshare/<file>', methods = ['POST'])
def unshare_file(file:str):
    if(not session.get('username')):
        abort(401)
    username = session.get('username')
    status = funcs.unshare_file(file, username)
    flash(status[1], 'success' if status[0] else 'error')
    return redirect(url_for('router.show_file_info', file = file))

@router.route('/account', methods = ['GET', 'POST'])
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

@router.route('/delete/<file>', methods = ['POST'])
def delete_file(file:str):
    if(not session.get('username')):
        abort(401)
    username = session.get('username')
    if(request.method == 'POST'):
        status = funcs.delete_file(file, username)
        flash(status[1], 'success' if status[0] else 'error')
    return redirect(url_for('router.download_file_page'))

@router.route('/share/<file>', methods = ['POST'])
def share_file(file):
    if(not session.get('username')):
        abort(401)
    username = session.get('username')
    status = funcs.share_file(file, username)
    flash(status[1], 'success' if status[0] else 'error')
    return redirect(url_for('router.show_file_info', file = file))

@router.route('/download/<file>', methods = ['POST'])
@router.route('/shared_file_download/<file>', methods = ['POST'])
def send_file(file:str):
    if(not session.get('username')):
        return redirect('/login')
    username = session.get('username')
    file_download_form = forms.FileDownloadForm()
    if(file_download_form.validate_on_submit()):
        if(request.path.startswith('/download/')):
            file = database_funcs.get_file_data_by_filename(file, username)
        else:
            file = database_funcs.get_file_data_by_share_url(file)
        if(file is not None and os.path.isfile(os.path.join('files', file.owner_uuid, file.internal_filename))):
            current_app.logger.info(f'{username} downloaded a file: {file.public_filename}', {'log_type': 'file download'})
            return send_from_directory(os.path.join('files', file.owner_uuid), file.internal_filename, download_name = file.public_filename, as_attachment = True)
        else:
            abort(404)
    else:
        abort(403)

@router.route('/shared_files/<shareURL>')
def show_shared_file_info(shareURL:str):
    if(not session.get('username')):
        abort(404)
    username = session.get('username')
    file_download_form = forms.FileDownloadForm()
    file = database_funcs.get_file_data_by_share_url(shareURL)
    if file is None:
        abort(404)
    return render_template('files.html', file = file, file_download_form = file_download_form)

@router.route('/files/<file>')
def show_file_info(file:str):
    if(not session.get('username')):
        abort(404)
    username = session.get('username')
    file_download_form = forms.FileDownloadForm()
    file_delete_form = forms.FileDeleteForm()
    file_share_form = forms.FileShareForm()
    file_unshare_form = forms.FileUnshareForm()
    file = database_funcs.get_file_data_by_filename(file, username)
    return render_template('files.html', file=file, file_download_form = file_download_form, file_delete_form = file_delete_form,
                                                                   file_share_form = file_share_form, file_unshare_form = file_unshare_form)

@router.route('/download')
def download_file_page():
    if(not session.get('username')):
        abort(401)
    username = session.get('username')
    number_of_all_files = database_funcs.get_file_count_by_user(username)
    try:
        file_start = int(request.args.get('start', 0))
    except ValueError:
        file_start = 0
    files = funcs.get_file_list(username, file_start)
    return render_template("file_download.html", files = files, number_of_files = len(files), number_of_all_files = number_of_all_files)

@router.route('/admin', methods = ['GET', 'POST'])
def admin():
    def fill_config_change_form():
        for field in config_funcs.read_configurable_data_file():
            setattr(forms.AdminPanelConfigChangeFormBase, field.config_name, field.create_field())
    
    if(not admin_funcs.is_admin(session.get('username'))):
        abort(404)
    
    username = session.get('username')
    fill_config_change_form()
    config_update_form = forms.AdminPanelConfigChangeFormBase(**config_funcs.get_configurable_data_values(stringify=True))
    account_create_form = forms.AdminPanelAccountCreateForm()
    if(account_create_form.validate_on_submit()):
        new_account_username = account_create_form.data['username']
        password = account_create_form.data['password']
        permissions = account_create_form.data['permissions']
        account_creation_status = admin_funcs.create_account(new_account_username, password, permissions)
        flash(account_creation_status[1], 'success' if account_creation_status[0] else 'error')
    elif(config_update_form.validate_on_submit()):
        new_config_data = config_update_form.data
        new_config_data.pop('action', None)
        status = config_funcs.update_configurable_data(new_config_data)
        flash(status[1], 'success' if status[0] else 'error')
    return render_template('admin.html', account_create_form = account_create_form, config_update_form = config_update_form)

@router.route('/login', methods = ['GET', 'POST'])
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

@router.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/')

@router.route('/')
def index():
    return render_template('index.html')
