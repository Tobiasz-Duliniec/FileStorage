'''
Main file for the website.
'''

from flask import Flask
import classes.log_formatters
import funcs.config as config_funcs
import funcs.functions as funcs
import logging.config
import os
import shutil


def create_app():
    app = Flask(__name__, static_folder=None)
    
    if(not os.path.isdir(os.path.join(app.root_path, 'instance'))):
        os.mkdir('instance')
    if(not os.path.isdir(os.path.join(app.root_path, 'instance', 'logs'))):
        os.mkdir(os.path.join(app.root_path, 'instance', 'logs'))
    if(not os.path.isdir(os.path.join(app.root_path, 'instance', 'files'))):
        os.mkdir(os.path.join(app.root_path, 'instance', 'files'))
    if(not os.path.isfile(os.path.join(app.root_path, 'instance', 'configurable_data.json'))):
        shutil.copy(os.path.join(app.root_path, 'configurable_data.json'), os.path.join(app.root_path, 'instance', 'configurable_data.json'))
    
    logging.getLogger('werkzeug').disabled = True
    logging.config.dictConfig({
        'version': 1,
        'formatters': {
            'default': {
                '()': 'classes.log_formatters.ConsoleFormatter',
                'format': '%(levelname)s | Time: %(asctime)s | IP: %(ip)s | Username: %(username)s | Method: %(method)s | URL: %(url)s | Status code: %(status_code)s ' \
                '| User agent: %(user_agent)s | Log type: %(log_type)s | Message: %(message)s',
                'datefmt': '%Y-%d-%m %H:%M:%S'
            },
            'JSON_Lines': {
                '()': 'classes.log_formatters.JSONLinesFormatter',
                'datefmt': '"%Y-%m-%d %H:%M:%S"'
            }
        },
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'stream': 'ext://sys.stdout',
                'formatter': 'default'
            },
            'JSON_Lines_file': {
                'class': 'logging.handlers.RotatingFileHandler',
                'formatter': 'JSON_Lines',
                'filename': 'instance/logs/logs.jsonl',
                'encoding': 'UTF-8',
                'maxBytes': 10 * 1024 * 1024 * 1024,
                'backupCount': 10
            }
        },
        'root': {
            'handlers': ('console', 'JSON_Lines_file'),
            'level': 'INFO'
        }
    })
    
    
    app.logger.info('FileStorage is being launched...')
    app.jinja_env.lstrip_blocks = True
    app.jinja_env.trim_blocks = True
    
    
    with app.app_context():
        config_funcs.set_configurable_data()
        from routes import router
        from funcs.context_processor import context_processor_funcs_blueprint
        from errors import Errors
        app.register_blueprint(router)
        app.register_blueprint(context_processor_funcs_blueprint)
        app.register_blueprint(Errors)
        funcs.check_database()
    
    app.logger.info('Start up script finished.')
    return app