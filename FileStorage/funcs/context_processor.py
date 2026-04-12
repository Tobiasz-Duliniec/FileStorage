from flask import Blueprint, session
import funcs.admin as admin_funcs 

context_processor_funcs_blueprint = Blueprint('administration', __name__)

@context_processor_funcs_blueprint.app_context_processor
def is_admin_jinja():
    return {'is_admin': admin_funcs.is_admin(session.get('username'))}