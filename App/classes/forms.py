'''
HTML forms definitions
'''

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

class AdminPanelConfigChangeFormBase(FlaskForm):
    action = HiddenField('action', default = 'config')
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
    submit_button = SubmitField('Upload')

class LoginForm(FlaskForm):
    username = StringField('Username', validators = [InputRequired()])
    password = PasswordField('Password', validators = [InputRequired()])
    submit = SubmitField('Login')

class PasswordResetForm(FlaskForm):
    current_password = PasswordField('Current password', validators = [InputRequired()])
    new_password = PasswordField('New password', validators = [InputRequired()])
    confirm_password = PasswordField('Confirm new password', validators = [InputRequired()])
    submit = SubmitField('Change password')
