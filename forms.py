from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, URL

class UserAddForm(FlaskForm):
    """Form for adding users."""
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    image_url = StringField('(Optional) Image URL', validators=[URL(), Length(max=200)], default="")

class LoginForm(FlaskForm):
    """Login form."""
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class MessageForm(FlaskForm):
    """Form for adding/editing messages."""
    text = TextAreaField('Message', validators=[DataRequired(), Length(max=140)])

class UserProfileForm(FlaskForm):
    """Form for updating user profile."""
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    image_url = StringField('Image URL', validators=[URL(), Length(max=200)], default="")
    header_image_url = StringField('Header Image URL', validators=[URL(), Length(max=200)], default="")
    bio = TextAreaField('Bio', validators=[Length(max=300)])
    password = PasswordField('Password', validators=[DataRequired()])