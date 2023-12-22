from flask_wtf import FlaskForm
from wtforms import EmailField, PasswordField, StringField, SubmitField, IntegerField
from wtforms.validators import DataRequired, Email


class LoginForm(FlaskForm):
    email = EmailField(validators=[DataRequired(message="The email field is required"), Email()])
    password = PasswordField(validators=[DataRequired(message="The password field is required")])
    submit = SubmitField()


class RegisterForm(FlaskForm):
    email = EmailField(validators=[DataRequired(message="The email field is required"), Email()])
    password = PasswordField(validators=[DataRequired(message="The password field is required")])
    conf_password = PasswordField(validators=[DataRequired(message="The Confirm password field is required")])
    submit = SubmitField()


class TwoFaForm(FlaskForm):
    code = StringField(validators=[DataRequired(message="Please enter code from your Authenticator App")])
    submit = SubmitField(label="Setup 2FA")
