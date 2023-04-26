from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Email, Length

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Contraseña", validators=[DataRequired()])
    remember_me = BooleanField("Recuérdame")
    submit = SubmitField("Iniciar sesión")

class SignupForm(FlaskForm):
    name = StringField("Nombre", validators=[DataRequired(), Length(max=64)])
    password = PasswordField("Contraseña", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Registrar")
