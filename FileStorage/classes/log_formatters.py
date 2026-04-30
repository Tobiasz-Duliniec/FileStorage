from flask import has_request_context, request, session
import json
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
            record.ip = request.remote_addr
            record.username = username
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
            record.log_type = 'startup process'

        log_entry = {
            "levelname": record.levelname,
            "time": record.asctime,
            "ip": record.ip,
            "username": record.username,
            "method": record.method,
            "url": record.url,
            "status_code": record.status_code,
            "user_agent": str(record.user_agent),
            "log_type": record.log_type,
            "message": record.getMessage(),
            "exc_info": self.formatException(record.exc_info) if record.exc_info is not None else None
        }

        return json.dumps(log_entry)