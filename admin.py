'''
File for admin functions.
'''

from flask import abort, Blueprint, current_app, flash, render_template, request, session
import json
import sqlite3

admin_panel = Blueprint('administration', __name__)


def is_admin(username) -> bool:
    if(username is None):
        return False
    with sqlite3.connect('users.db') as conn:
        cur = conn.cursor()
        permissions = cur.execute('''SELECT permissions
                            FROM users
                            WHERE username=?;''',
                            (username, )).fetchone()[0]
        cur.close()
    return True if permissions == 1 else False

@admin_panel.app_context_processor
def is_admin_jinja():
    return {'is_admin': is_admin(session.get('username'))}

@admin_panel.route('/admin', methods = ['GET', 'POST'])
def admin():
    if(not is_admin(session.get('username'))):
        abort(404)
    if(request.method == 'POST'):
        if(request.form['action'] == 'config'):
            new_config_data = dict(request.form)
            new_config_data.pop('action', None)
            new_config_data['SESSION_COOKIE_HTTPONLY'] = bool(new_config_data['SESSION_COOKIE_HTTPONLY'])
            for x in ('MAX_FILE_SIZE_GB', 'MAX_FILES_PER_PAGE', 'MAX_FILENAME_LENGTH', 'PERMANENT_SESSION_LIFETIME'):
                try:
                    new_config_data[x] = int(new_config_data[x])
                except ValueError:
                    flash(f'Error: invalid data type in the following field: {x}', 'error')
                    break
            else:
                current_app.config.from_mapping(new_config_data)
                with open('config.json', 'wt', encoding = 'utf-8') as config_file:
                    json.dump(new_config_data, config_file, indent = 1)
                flash('config settings have been updated.', 'success')
        elif(request.form['action'] == 'register'):
            username = request.form.get('username')
            password = request.form.get('password', 'password')
            password = bcrypt.hashpw(password.encode('utf-8'), current_app.config['GENSALT'])
            user_UUID = str(uuid.uuid4())
            permissions = request.form.get('permissions', '0')
            with sqlite3.connect('users.db') as conn:
                cur = conn.cursor()
                try:
                    cur.execute('INSERT INTO users(username, password, UUID, permissions) VALUES (?, ?, ?, ?)', (username, password, user_UUID, permissions))
                    flash('New account created.', 'success')
                except sqlite3.IntegrityError as e:
                    flash(f'Account creation failed: {e}', 'error')
                cur.close()
    with open('config.json', 'rt', encoding = 'utf-8') as config_file:
        config_data = json.load(config_file)
    return render_template('admin.html', config_data = config_data)
