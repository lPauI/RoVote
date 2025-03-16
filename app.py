from flask import Flask, render_template
from flask_wtf import CSRFProtect, FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
from flask_sqlalchemy import SQLAlchemy

from dotenv import load_dotenv
from os import getenv
from bcrypt import hashpw, gensalt, checkpw

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = getenv('FLASK_SECRET_KEY')
csrf = CSRFProtect(app)

mysql_user = getenv('MYSQL_USER')
mysql_password = getenv('MYSQL_PASSWORD')
mysql_host = getenv('MYSQL_HOST')
mysql_database = getenv('MYSQL_DATABASE')

app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{mysql_user}:{mysql_password}@{mysql_host}/{mysql_database}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')
    
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
    
@app.route("/auth/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    error = None
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        
        user = Users.query.filter_by(email=email).first()
        
        if not user:
            error = "Email-ul nu a fost gasit."
            return render_template('auth/login.html', form=form, error=error)
        
        if not checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            error = "Parola este invalida."
            return render_template('auth/login.html', form=form, error=error)
            
        return render_template("index.html")
    return render_template('auth/login.html', form=form, error=error)

@app.route('/auth/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        
        password = hashpw(password.encode('utf-8'), gensalt()).decode('utf-8')

        new_user = Users(email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        
        return render_template("index.html")
    
    return render_template('auth/register.html', form=form)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    app.run(host='0.0.0.0', port=5000, debug=True)