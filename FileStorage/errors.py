'''
File for custom error pages.
'''

from flask import Blueprint, current_app, flash, render_template


Errors = Blueprint('error', __name__)

@Errors.app_errorhandler(500)
def internal_server_error(e):
    flash('Internal Server Error: something went wrong when processing your request.', 'error')
    return render_template('error.html'), 500

@Errors.app_errorhandler(413)
def request_entity_too_large(e):
    plural = 's' if current_app.config['MAX_FILE_SIZE_GB'] != 1 else ""
    flash(f"Requested Entity Too Large: you cannot upload files larger than {current_app.config['MAX_FILE_SIZE_GB']} gigabyte{plural}.", 'error')
    return render_template('file_upload.html'), 413

@Errors.app_errorhandler(404)
def page_not_found(e):
    flash("Page Not Found: requested page couldn't be found.")
    return render_template('error.html'), 404

@Errors.app_errorhandler(401)
def unauthorized(e):
    flash('Unauthorized: you need to log in to view this page.')
    return render_template('error.html'), 401
