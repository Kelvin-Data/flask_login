# wtform
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms import validators, ValidationError
from wtforms.validators import DataRequired, EqualTo

class LoginForm(FlaskForm):
    username = StringField('Username', 
                           [validators.DataRequired('Username')])
    password = PasswordField('Password', 
                             [validators.DataRequired('Password')])
    submit = SubmitField('Login')
    

class UserForm(FlaskForm):
	name = StringField("Name", [validators.DataRequired('Name')])
	username = StringField("Username", [validators.DataRequired('Username')])
	email = StringField("Email", [validators.DataRequired('Email')])
	password_hash = PasswordField('Password', [validators.DataRequired('Password')])
	submit = SubmitField("Submit")
 
class LogoutForm(FlaskForm):
     submit = SubmitField("Logout")