from flask import (Flask, redirect, url_for, render_template,
                   request, flash)
from flask_login import (LoginManager, login_user, logout_user,
                          current_user, login_required)
from form import LoginForm, UserForm, LogoutForm
from werkzeug.security import generate_password_hash, check_password_hash

# create the app
app=Flask(__name__)
app.config['SECRET_KEY'] = 'kelvin python'

#### 1) SQlalchemy ####
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///user.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# create the extension
db = SQLAlchemy(app)

# initialize the app with the extension
db.init_app(app)

# Create Model
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    name = db.Column(db.String(20))
    password_hash = db.Column(db.String(128))
   
     
def __init__(self, username, name, password_hash):
    self.username = username
    self.name = name
    self.password_hash = password_hash
   
# Create db and table   
# db.create_all()

#### 2) Flask-login ####
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Create Dashboard Page
@app.route('/')
def home():
    return render_template('base.html')

# Create Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # .first() if exist then validate because the username is unique
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            # check the hash
            if check_password_hash(user.password_hash, form.password.data):
                # if login successful
                login_user(user)
                return redirect(url_for('dashboard'))
                flash('Yeah, You have Logged In!')
            else:
                flash("Oh no, Your Password Is Incorrect!")
        else:
            flash("Sorryy.., No Such User!")
    return render_template('login.html', form = form)

# Create Dashboard Page
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = LogoutForm()
    return render_template('dashboard.html', form = form)

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

# Create log out
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash("You Have Logged Out Now")
    return redirect(url_for('login'))

##### Register ####
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = UserForm()
    if request.method == 'POST':
        # when field leave blank
        if not request.form['name'] or not request.form['username'] or not request.form['password_hash']:
            flash('Please enter all fields!', 'error')
        else:
            # when all fields fill out
            name = request.form['name']
            username = request.form['username'] 
            password = request.form['password_hash']
            # Hash the password!!!
            hashed_pw = generate_password_hash(password)
            user = Users(name = name, username = username, password_hash = hashed_pw)
            
            ### Database operation ###
            db.session.add(user)
            db.session.commit()
            
            flash('Record was successfully record!')
           
    # if not success remain in new page
    return render_template('register.html', form = form) 


if __name__ == '__main__':
    app.run(port=5000,debug=True)
    
# pip install flask_login
# https://flask-login.readthedocs.io/en/latest/
# http://127.0.0.1:5000/login

'''
username    password
Kelvin      password123
Lisa        password123
Peter       password123
David       password
'''

# def home() -------------------> base.html
# render_template('base.html')    href="{{ url_for('register')}}"
                                # href="{{ url_for('login')}}"
                        
#### Register ####
# def register() ------------------> register.html
# render_template('register.html')


#### Login ####
# def login() ---------------------> login.html ------> def dashboard()
# render_template('login.html')                        render_template('dashboard.html')

# ----> dashboard.html ---------------> def logout()
#       action="{{ url_for('logout')}}  redirect(url_for('login'))