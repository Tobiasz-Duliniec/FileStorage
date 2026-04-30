'''
Logging related functions
'''

'''
from flask import Blueprint, current_app, request
import classes.log_formatters
import logging.config

logger_functions = Blueprint('logging_functions', __name__)

def configure_loggers():
    logging.getLogger('werkzeug').disabled = True
    logging.config.dictConfig({
        'version': 1,
        'formatters': {
            'default': {
                '()': 'classes.log_formatters.ConsoleFormatter',
                'format': '%(levelname)s | Time: %(asctime)s | IP: %(ip)s | Username: %(username)s | Method: %(method)s | URL: %(url)s | Status code: %(status_code)s | User agent: %(user_agent)s | Log type: %(log_type)s | Message: %(message)s',
                'datefmt': '%Y-%d-%m %H:%M:%S'
            },
            'JSON_Lines': {
                '()': 'classes.log_formatters.JSONLinesFormatter',
                'format': '{"levelname": "%(levelname)s", "time": %(asctime)s, "ip": %(ip)s, "username": %(username)s, "method": %(method)s, "url": %(url)s, "status_code": %(status_code)s, "user_agent": %(user_agent)s, "log_type": "%(log_type)s", "message": "%(message)s"}',
                'datefmt': '"%Y-%d-%m %H:%M:%S"'
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

@logger_functions.after_request
def http_request_logger(response):
    request.status_code = response.status_code
    request.user_agent = request.headers.get('User-Agent')
    current_app.logger.info('A HTTP finished processing.', {'log_type': 'HTTP request'})
    return response
'''