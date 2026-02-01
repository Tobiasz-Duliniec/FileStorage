'''
HTML forms definitions
'''

from bs4 import BeautifulSoup
from flask import current_app
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import BooleanField, HiddenField, IntegerField, PasswordField, SelectField, StringField, SubmitField
from wtforms.validators import InputRequired
import funcs.config as config_funcs


class AdminPanelAccountCreateForm(FlaskForm):
    username = StringField('username', validators = [InputRequired()])
    password = PasswordField('password', validators = [InputRequired()])
    permissions = SelectField('permissions', choices = [('0', 'User'), ('1', 'Admin')])
    submit_button = SubmitField('Register new account')

class AdminPanelConfigChangeForm(FlaskForm):
    action = HiddenField('action', default = 'config')
    BANNED_CHARACTERS = StringField('BANNED_CHARACTERS')
    GENSALT = StringField('GENSALT', validators = [InputRequired()])
    MAX_FILE_SIZE_GB = IntegerField('MAX_FILE_SIZE', validators = [InputRequired()])
    MAX_FILES_PER_PAGE = IntegerField('MAX_FILES_PER_PAGE', validators = [InputRequired()])
    MAX_FILENAME_LENGTH = IntegerField('MAX_FILENAME_LENGTH', validators = [InputRequired()])
    PERMANENT_SESSION_LIFETIME = IntegerField('PERMANENT_SESSION_LIFETIME', validators = [InputRequired()])
    SECRET_KEY = StringField('SECRET_KEY', validators = [InputRequired()])
    SEND_ROBOTS_TXT = BooleanField('SEND_ROBOTS_TXT')
    SESSION_COOKIE_HTTPONLY = BooleanField('SESSION_COOKIE_HTTPONLY')
    SESSION_COOKIE_SAMESITE = SelectField('SESSION_COOKIE_SAMESITE', choices = [('Lax', 'Lax'), ('Strict', 'Strict')])
    SESSION_COOKIE_SECURE = BooleanField('SESSION_COOKIE_SECURE')
    submit_button = SubmitField('Save config')
            
class FileDeleteForm(FlaskForm):
    action = HiddenField('action', default = 'deleteFile')
    submit_button = SubmitField('Delete file')

class FileDownloadForm(FlaskForm):
    action = HiddenField('action', default = 'downloadFile')
    submit_button = SubmitField('Download file')

class FileShareForm(FlaskForm):
    action = HiddenField('action', default = 'shareFile')
    submit_button = SubmitField('Share file')

class FileUnshareForm(FlaskForm):
    action = HiddenField('action', default = 'unshareFile')
    submit_button = SubmitField('Unshare file')

class FileUploadForm(FlaskForm):
    file = FileField('file', validators = [FileRequired()])
    submit_button = SubmitField('Submit')

class LoginForm(FlaskForm):
    username = StringField('Username', validators = [InputRequired()])
    password = PasswordField('Password', validators = [InputRequired()])
    submit = SubmitField('Submit')

class PasswordResetForm(FlaskForm):
    current_password = PasswordField('Current password', validators = [InputRequired()])
    new_password = PasswordField('New password', validators = [InputRequired()])
    confirm_password = PasswordField('Confirm new password', validators = [InputRequired()])
    submit = SubmitField('Change password')
