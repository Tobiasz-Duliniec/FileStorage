'''
File for admin panel functionality.
'''

from bs4 import BeautifulSoup
from flask import abort, Blueprint, current_app, flash, render_template, request, session
import bcrypt
import forms
import funcs.config as config_funcs
import json
import os
import sqlite3
import uuid


admin_panel = Blueprint('administration', __name__)

def validate_new_data(to_check) -> dict:
    type_functions = {
        'bool': bool,
        'bytes': bytes,
        'int': int,
        'str': str,
        'list': list
    }
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
    return element

@admin_panel.app_context_processor
def is_admin_jinja():
    return {'is_admin': is_admin(session.get('username'))}

def create_account(username:str, password:str, permissions:str) -> tuple[bool, str]:
    if(username is None or password is None or permissions is None):
        current_app.logger.error(f'Missing data during account creation.', {'log_type': 'account'})
        return (False, 'Please input username, password, and permissions.')
    password = bcrypt.hashpw(password.encode('utf-8'), current_app.config['GENSALT'])
    user_UUID = str(uuid.uuid4())
    with sqlite3.connect(os.path.join('instance', 'users.db')) as conn:
        cur = conn.cursor()
        try:
            cur.execute('INSERT INTO users(username, password, UUID, permissions) VALUES (?, ?, ?, ?)', (username, password, user_UUID, permissions))
            cur.close()
            os.makedirs(os.path.join('files', user_UUID))
            current_app.logger.info(f'New account has been created: {username}', {'log_type': 'account'})
            return (True, 'New account created.')
        except sqlite3.IntegrityError as e:
            cur.close()
            current_app.logger.error(f'Account creation failed: {e}.', {'log_type': 'account'})
            return (False, f'Account creation failed: {e}')

def update_configs(config_data:dict) -> tuple[bool, str]:
            config_data = validate_new_data(config_data)
            if(len(config_data) > 0):
                current_app.config.from_mapping(config_data)
                config_funcs.save_configurable_data(config_data)
                current_app.config['MAX_CONTENT_LENGTH'] = current_app.config['MAX_FILE_SIZE_GB'] * 1024 * 1024 * 1024
                current_app.logger.info('Config data successfully updated.', {'log_type': 'config'})
                return (True, 'Config settings have been updated.' )
            else:
                current_app.logger.error('An error occured while updating config.', {'log_type': 'config'})
                return (False, '''An error has occured when updating your data. Is the data you provided correct? Make sure you have sent
                            all data for all fields. For numerical values (like MAX_FILENAME_LENGTH) value must be greater than 0.''')

@admin_panel.route('/admin', methods = ['GET', 'POST'])
def admin():
    if(not is_admin(session.get('username'))):
        abort(404)
    username = session.get('username')
    config_update_form = forms.AdminPanelConfigChangeForm(**config_funcs.get_configurable_data_values())
    account_create_form = forms.AdminPanelAccountCreateForm()
    if(account_create_form.validate_on_submit()):
        new_account_username = account_create_form.data['username']
        password = account_create_form.data['password']
        permissions = account_create_form.data['permissions']
        account_creation_status = create_account(new_account_username, password, permissions)
        flash(account_creation_status[1], 'success' if account_creation_status[0] else 'error')
    elif(config_update_form.validate_on_submit()):
        new_config_data = config_update_form.data
        new_config_data.pop('action', None)
        status = update_configs(new_config_data)
        flash(status[1], 'success' if status[0] else 'error')
    return render_template('admin.html', account_create_form = account_create_form, config_update_form = config_update_form)
