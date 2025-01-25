'''
File for admin functions.
'''

from bs4 import BeautifulSoup
from flask import abort, Blueprint, current_app, flash, render_template, request, session
import bcrypt
import funcs
import json
import os
import sqlite3
import uuid


admin_panel = Blueprint('administration', __name__)

type_functions = {
    'bool': bool,
    'bytes': bytes,
    'int': int,
    'str': str,
    'list': list
}

def validate_new_data(to_check) -> dict:
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
                elif(config_type == 'int'):
                    converted_data[config_name] = expected_type_func(to_check[config_name])
                    if(converted_data[config_name] <= 0):
                        raise ValueError
                elif(config_type == 'bool'):
                    converted_data[config_name] = expected_type_func(int(to_check[config_name]))
                else:
                    converted_data[config_name] = expected_type_func(to_check[config_name])
                    if(converted_data[config_name] == ''):
                        raise ValueError
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
    return permissions == 1

def prepare_configs(element):
    if(isinstance(element, list)):
        return "".join(element)
    elif(isinstance(element, bytes)):
        return element.decode()
    else:
        return element

@admin_panel.app_context_processor
def is_admin_jinja():
    return {'is_admin': is_admin(session.get('username'))}

@admin_panel.app_context_processor
def get_config_value():
    def get_value(value_name):
        return prepare_configs(current_app.config.get(value_name, None))
    return {'get_config_value': get_value}

@admin_panel.route('/admin', methods = ['GET', 'POST'])
def admin():
    if(not is_admin(session.get('username'))):
        abort(404)
    if(request.method == 'POST'):
        if(request.form['action'] == 'config'):
            new_config_data = dict(request.form)
            new_config_data.pop('action', None)
            new_config_data = validate_new_data(new_config_data)
            if(len(new_config_data) > 0):
                current_app.config.from_mapping(new_config_data)
                funcs.save_configs(new_config_data)
                current_app.config['MAX_CONTENT_LENGTH'] = current_app.config['MAX_FILE_SIZE_GB'] * 1024 * 1024 * 1024
                flash('Config settings have been updated.', 'success')
            else:
                flash(f'''An error has occured when updating your data. Is the data you provided correct? Make sure you have sent
                            all data for all fields. For numerical values (like MAX_FILENAME_LENGTH) value must be greater than 0.''', 'error')
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
    
    config_data = funcs.get_configs()
    return render_template('admin.html', config_data = config_data, config_types = tuple(type_functions))
