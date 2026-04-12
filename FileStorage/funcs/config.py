from bs4 import BeautifulSoup
from flask import current_app
import bcrypt
import json
import os


def get_configurable_data_values() -> dict:
    config_data = {}
    with open(os.path.join(current_app.root_path, 'configurable_data.xml'), 'rt', encoding = 'UTF-8') as file:
        parsed_file = BeautifulSoup(file, 'xml')
        for element in parsed_file.find_all('config'):
            config_name = element.find('name').text
            config_value = current_app.config[config_name]
            if(isinstance(config_value, list)):
                config_value = ''.join(config_value)
            elif(isinstance(config_value, bytes)):
                config_value = config_value.decode()
            config_data[config_name] = config_value
    return config_data

def save_configurable_data(configs:dict) -> None:
    config_data = {}
    with open(os.path.join(current_app.root_path, 'configurable_data.xml'), 'rt', encoding = 'UTF-8') as file:
        parsed_file = BeautifulSoup(file, 'xml')
        for element in parsed_file.find_all('config'):
            config_name = element.find('name').text
            if(isinstance(configs[config_name], bytes)):
                config_data[config_name] = configs[config_name].decode()
            else:
                config_data[config_name] = configs[config_name]
    with open(os.path.join('instance', 'config.json'), 'wt', encoding='utf-8') as file:
        json.dump(config_data, file, indent = 1)

def set_configurable_data() -> None:
    '''
    Loads data from config file if it exists.
    If it doesn't, it generates one.
    '''
    current_app.logger.info('Checking config settings.')
    if(os.path.isfile(os.path.join('instance', 'config.json'))):
        current_app.logger.info('Config file found. Importing.')
        current_app.config.from_file(os.path.join('instance', 'config.json'), load = json.load)
        current_app.config['GENSALT'] = current_app.config['GENSALT'].encode('utf-8')
        current_app.config['SECRET_KEY'] = current_app.config['SECRET_KEY'].encode('utf-8')
    else:
        current_app.logger.info('Config file not found: using default config settings.')
        current_app.config['BANNED_CHARACTERS'] = ['<', '>', '"', "'",  '\\', '/', ':', '|', '?', '*', '#']
        current_app.config['GENSALT'] = bcrypt.gensalt()
        current_app.config['MAX_FILE_SIZE_GB'] = 1
        current_app.config['MAX_FILES_PER_PAGE'] = 30
        current_app.config['MAX_FILENAME_LENGTH'] = 32
        current_app.config['PERMANENT_SESSION_LIFETIME'] = 10800
        current_app.config['SECRET_KEY'] = bcrypt.gensalt()
        current_app.config['SEND_ROBOTS_TXT'] = False
        current_app.config['SESSION_COOKIE_HTTPONLY'] = True
        current_app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
        current_app.config['SESSION_COOKIE_SECURE'] = False
        save_configurable_data(current_app.config)
    current_app.config['MAX_CONTENT_LENGTH'] = current_app.config['MAX_FILE_SIZE_GB'] * 1024 * 1024 * 1024
    current_app.logger.info('Config settings set up.')

def update_configurable_data(config_data:dict) -> tuple[bool, str]:
    config_data = validate_new_configurable_data(config_data)
    if(len(config_data) > 0):
        current_app.config.from_mapping(config_data)
        save_configurable_data(config_data)
        current_app.config['MAX_CONTENT_LENGTH'] = current_app.config['MAX_FILE_SIZE_GB'] * 1024 * 1024 * 1024
        current_app.logger.info('Config data successfully updated.', {'log_type': 'config'})
        return (True, 'Config settings have been updated.' )
    else:
        current_app.logger.error('An error occured while updating config.', {'log_type': 'config'})
        return (False, '''An error has occured when updating your data. Is the data you provided correct? Make sure you have sent
                    all data for all fields. For numerical values (like MAX_FILENAME_LENGTH) value must be greater than 0.''')

def validate_new_configurable_data(to_check) -> dict:
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
