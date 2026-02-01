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

def get_configurable_data_types() -> dict:
    config_data = {}
    with open(os.path.join(current_app.root_path, 'configurable_data.xml'), 'rt', encoding = 'UTF-8') as file:
        parsed_file = BeautifulSoup(file, 'xml')
        for element in parsed_file.find_all('config'):
            config_name = element.find('name').text
            config_type = element.find('type').text
            config_data[config_name] = config_type
    return config_data

def save_configs(configs:dict) -> None:
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

def set_configs() -> None:
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
        save_configs(current_app.config)
    current_app.config['MAX_CONTENT_LENGTH'] = current_app.config['MAX_FILE_SIZE_GB'] * 1024 * 1024 * 1024
    current_app.logger.info('Config settings set up.')

