'''
File for admin functions.
'''

from bs4 import BeautifulSoup
from flask import abort, Blueprint, current_app, flash, render_template, request, session
import funcs
import json
import os
import sqlite3

admin_panel = Blueprint('administration', __name__)

type_functions = {
    'bool': bool,
    'bytes': bytes,
    'int': int,
    'str': str,
    'list': list
}

def set_new_data(to_check) -> dict:
    converted_data = {}
    with open('configurable_data.xml', 'rt') as file:
        parsed_file = BeautifulSoup(file, 'xml')
        for element in parsed_file.find_all('config'):
            config_name = element.find('name').text
            config_type = element.find('type').text
            try:
                expected_type_func = type_functions[config_type]
                if(config_type == 'bytes'):
                    converted_data[config_name] = expected_type_func(to_check[config_name], encoding = 'utf-8')
                elif(config_type == 'bool'):
                    converted_data[config_name] = expected_type_func(int(to_check[config_name]))
                else:
                    converted_data[config_name] = expected_type_func(to_check[config_name])
            except ValueError:
                return {}
    return converted_data

def is_admin(username:str) -> bool:
    if(username is None):
        return False
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        permissions = cur.execute('''SELECT permissions
                            FROM users
                            WHERE username=?;''',
                            (username, )).fetchone()[0]
        cur.close()
    return True if permissions == 1 else False

def prepare_configs(elements) -> dict:
    configurable_options = {}
    for element in elements:
        if(isinstance(elements[element], list)):
            configurable_options[element] =  ''.join(elements[element])
        else:
            configurable_options[element] = elements[element]
    return configurable_options

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
            converted_data = set_new_data(new_config_data)
            if(len(converted_data) > 0):
                current_app.config.from_mapping(converted_data)
                funcs.save_configs(converted_data)
                flash('Config settings have been updated.', 'success')
            else:
                flash(f'An error has occured when updating your data. Is the data you provided correct?', 'error')
        elif(request.form['action'] == 'register'):
            username = request.form.get('username')
            password = request.form.get('password', 'password')
            password = bcrypt.hashpw(password.encode('utf-8'), current_app.config['GENSALT'])
            user_UUID = str(uuid.uuid4())
            permissions = request.form.get('permissions', '0')
            with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
                cur = conn.cursor()
                try:
                    cur.execute('INSERT INTO users(username, password, UUID, permissions) VALUES (?, ?, ?, ?)', (username, password, user_UUID, permissions))
                    flash('New account created.', 'success')
                except sqlite3.IntegrityError as e:
                    flash(f'Account creation failed: {e}', 'error')
                cur.close()
    with open(os.path.join('instance', 'config.json'), 'rt', encoding = 'utf-8') as config_file:
        config_data = json.load(config_file)
    return render_template('admin.html', config_data = prepare_configs(config_data))
