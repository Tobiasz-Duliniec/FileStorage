from flask import has_request_context, request, session
import logging

class ConsoleFormatter(logging.Formatter):
    def format(self, record):
        if(has_request_context()):
            record.ip = request.remote_addr
            record.username = session.get('username')
            record.method = request.method
            record.url = request.url
            record.status_code = request.status_code if hasattr(request, 'status_code') else None
            record.user_agent = request.user_agent
            record.log_type = 'An exception has occured' if record.levelno >= 40 else record.args.get('log_type', None) 
        else:
            record.ip = None
            record.username = None
            record.method = None
            record.url = None
            record.status_code = None
            record.user_agent = None
            record.log_type = 'start up process'
        return super().format(record)

class JSONLinesFormatter(logging.Formatter):
    def format(self, record):
        if(has_request_context()):
            username = session.get('username', None)
            record.ip = f'"{request.remote_addr}"'
            record.username = f'"{username}"' if username is not None else 'null'
            record.method = f'"{request.method}"'
            record.url = f'"{request.url}"'
            record.status_code = request.status_code if hasattr(request, 'status_code') else 'null'
            record.user_agent = f'"{request.user_agent}"'
            record.log_type = 'An exception has occured' if record.levelno >= 40 else record.args.get('log_type', None)
        else:
            record.ip = 'null'
            record.username = 'null'
            record.method = 'null'
            record.url = 'null'
            record.status_code = 'null'
            record.user_agent = 'null'
            record.log_type = 'startup process'
        return super().format(record)