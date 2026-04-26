from flask import current_app
from wtforms import BooleanField, IntegerField, SelectField, StringField
from wtforms.validators import InputRequired
import funcs.cryptography as crypto_funcs
import json
import os


class ConfigData:
    allowed_fields = {
        'StringField': StringField,
        'IntegerField': IntegerField,
        'BooleanField': BooleanField,
        'SelectField': SelectField
        }
    
    def __init__(self, config_name, config_type, config_value, config_form_type, config_form_choices, config_form_input_required):
        self.config_name = config_name
        self.config_type = config_type
        self.config_value = config_value
        self.config_form_type = config_form_type
        self.config_form_choices = config_form_choices
        self.config_form_input_required = config_form_input_required
    
    def __repr__(self):
        return f'ConfigData({self.config_name=}, {self.config_type}, {self.config_value=})'
    
    def create_field(self):
        if self.config_form_type == 'SelectField':
            form = SelectField(self.config_name, choices = self.config_form_choices, validators=[InputRequired()] if self.config_form_input_required else [])
        else:
            form = self.allowed_fields[self.config_form_type](self.config_name, validators=[InputRequired()] if self.config_form_input_required else [])
        return form

def read_configurable_data_file() -> list[ConfigData]:
    config_data = []
    with open(os.path.join('instance', 'configurable_data.json'), 'rt', encoding = 'UTF-8') as json_file:
        raw_config_data = json.load(json_file)
    for element in raw_config_data['configs']:
        config_name = element['name']
        config_type = element['type']
        config_value = element['value']
        config_form_type = element['form']['type']
        config_form_input_required = element['form']['input_required']
        if(config_form_type == 'SelectField'):
            config_choices = element['form']['choices']
        else:
            config_choices = None
        dana = ConfigData(config_name, config_type, config_value, config_form_type, config_choices, config_form_input_required)
        config_data.append(dana)
    return config_data

def get_configurable_data_values(stringify=False) -> dict:
    '''
    Returns a dict of config_name:config_value pairs.
    Optional parameters stringify turns lists into strings with ''.join()
    '''
    config_data = {}
    with open(os.path.join('instance', 'configurable_data.json'), 'rt', encoding = 'UTF-8') as file:
        raw_config_data = json.load(file)
    for element in raw_config_data['configs']:
        config_name = element['name']
        config_value = current_app.config[config_name]
        if(stringify):
            if(isinstance(config_value, list)):
                config_value = ''.join(config_value)
        config_data[config_name] = config_value
    return config_data

def save_configurable_data(configs:dict) -> None:
    with open(os.path.join('instance', 'configurable_data.json'), 'rt', encoding = 'UTF-8') as file:
        raw_config_data = json.load(file)
    for element in raw_config_data['configs']:
        config_name = element['name']
        element['value'] = configs[config_name]
    with open(os.path.join('instance', 'configurable_data.json'), 'wt', encoding='utf-8') as file:
        json.dump(raw_config_data, file, indent = 1)

def set_configurable_data() -> None:
    '''
    Loads data from config file if it exists.
    '''
    with open(os.path.join('instance', 'configurable_data.json')) as file:
        raw_config_data = json.load(file)
    new_config_data = {}
    update_file = False
    for element in raw_config_data['configs']:
        config_name = element['name']
        config_value = element['value']
        config_type = element['type']
        if(config_value == '[secret_key]'):
            config_value = crypto_funcs.generate_secret()
            update_file = True
        new_config_data[config_name] = config_value
    current_app.config.from_mapping(new_config_data)
    current_app.config['MAX_CONTENT_LENGTH'] = current_app.config['MAX_FILE_SIZE_GB'] * 1024 * 1024 * 1024
    current_app.logger.info('Config settings set up.')
    if(update_file):
        save_configurable_data(current_app.config)
        current_app.logger.info('Random value replaced with randomized value: config file updated.')

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
        'int': int,
        'str': str,
        'list': list
    }
    converted_data = {}
    with open(os.path.join('instance', 'configurable_data.json'), 'rt', encoding = 'UTF-8') as file:
        raw_json_file = json.load(file)
    for element in raw_json_file['configs']:
        config_name = element['name']
        config_type = element['type']
        try:
            expected_type_func = type_functions[config_type]
            if(config_type == 'int'):
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
