from wtforms import BooleanField, IntegerField, SelectField, StringField
from wtforms.validators import InputRequired


class ConfigData:
    __allowed_fields = {
        'StringField': StringField,
        'IntegerField': IntegerField,
        'BooleanField': BooleanField,
        'SelectField': SelectField
        }
    
    def __init__(self, config_name, config_type, config_value, config_form_type, config_form_choices, config_form_input_required):
        self.config_name = config_name
        self.config_type = config_type
        self.config_value = config_value
        self.config_form_type = config_form_type
        self.config_form_choices = config_form_choices
        self.config_form_input_required = config_form_input_required

    def create_field(self):
        if self.config_form_type == 'SelectField':
            form = SelectField(self.config_name, choices = self.config_form_choices, validators=[InputRequired()] if self.config_form_input_required else [])
        else:
            form = self.__allowed_fields[self.config_form_type](self.config_name, validators=[InputRequired()] if self.config_form_input_required else [])
        return form
