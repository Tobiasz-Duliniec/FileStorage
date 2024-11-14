'''
Different functions used by multiple files
'''

import json
import os


def save_configs(configs):
    config_data = {
        'BANNED_CHARACTERS': configs['BANNED_CHARACTERS'],
        'GENSALT': configs['GENSALT'].decode(),
        'MAX_FILE_SIZE_GB': configs['MAX_FILE_SIZE_GB'],
        'MAX_FILES_PER_PAGE': configs['MAX_FILES_PER_PAGE'],
        'MAX_FILENAME_LENGTH': configs['MAX_FILENAME_LENGTH'],
        'PERMANENT_SESSION_LIFETIME': configs['PERMANENT_SESSION_LIFETIME'],
        'SECRET_KEY': configs['SECRET_KEY'].decode(),
        'SESSION_COOKIE_HTTPONLY': configs['SESSION_COOKIE_HTTPONLY'],
        'SESSION_COOKIE_SAMESITE': configs['SESSION_COOKIE_SAMESITE'],
        'SESSION_COOKIE_SECURE': configs['SESSION_COOKIE_SECURE']
        }
    with open(os.path.join('instance', 'config.json'), 'wt', encoding='utf-8') as file:
        json.dump(config_data, file, indent = 1)
