'''
Main file for the website.
'''

from flask import Flask
import classes.log_formatters
import funcs.config as config_funcs
import funcs.funcs as funcs
import logging.config
import os
import shutil


def create_app():
    app = Flask(__name__, static_folder=None)
    
    
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
                'filename': 'logs.jsonl',
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
    
    
    app.logger.info('Starting website.')
    app.jinja_env.lstrip_blocks = True
    app.jinja_env.trim_blocks = True
    
    
    if(not os.path.isdir('instance')):
        app.logger.info('Instance folder not found. Creating.')
        os.mkdir('instance')
        shutil.copy(os.path.join('configurable_data.json'), os.path.join('instance', 'configurable_data.json'))
    
    
    with app.app_context():
        config_funcs.set_configurable_data()
        from routes import router
        from funcs.context_processor import context_processor_funcs_blueprint
        from errors import Errors
        app.register_blueprint(router)
        app.register_blueprint(context_processor_funcs_blueprint)
        app.register_blueprint(Errors)
        funcs.check_database()
    return app
