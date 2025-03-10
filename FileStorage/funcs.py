'''
Different functions used by multiple files
'''

from bs4 import BeautifulSoup
from flask import current_app
import json
import logging
import os


def get_configs() -> dict:
    config_data = {}
    with open('configurable_data.xml', 'rt', encoding = 'UTF-8') as file:
        parsed_file = BeautifulSoup(file, 'xml')
        for element in parsed_file.find_all('config'):
            config_name = element.find('name').text
            config_type = element.find('type').text
            config_data[config_name] = config_type
    return config_data

def save_configs(configs:dict) -> None:
    config_data = {}
    with open('configurable_data.xml', 'rt', encoding = 'UTF-8') as file:
        parsed_file = BeautifulSoup(file, 'xml')
        for element in parsed_file.find_all('config'):
            config_name = element.find('name').text
            if(isinstance(configs[config_name], bytes)):
                config_data[config_name] = configs[config_name].decode()
            else:
                config_data[config_name] = configs[config_name]
    with open(os.path.join('instance', 'config.json'), 'wt', encoding='utf-8') as file:
        json.dump(config_data, file, indent = 1)
