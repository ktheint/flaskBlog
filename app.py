from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from data import Articles
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps

app = Flask(__name__)
app.secret_key='super12345'


#config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'mysql123'
app.config['MYSQL_DB'] = 'myflaskapp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
#init MYSQL
mysql = MySQL(app)

Articles = Articles()


@app.route('/')
@app.route('/index')
def home():
    return render_template('home.html')

@app.route('/about')
def contact():
	return render_template('contact.html')

@app.route('/articles')
def articles():
	return render_template('articles.html', articles = Articles)

@app.route('/article/<string:id>/')
def article(id):
	return render_template('article.html', id = id)

#register form class
class RegisterForm(Form):
	name = StringField('Name', [validators.Length(min=1, max=50)])
	username = StringField('Username', [validators.Length(min=4, max=25)])
	email = StringField('Email', [validators.Length(min=6, max=50)])
	password = PasswordField('Password', [
		validators.DataRequired(),
		validators.EqualTo('confirm', message='Password do not match')
	])
	confirm = PasswordField('Confirm Password')

@app.route('/register', methods=['GET', 'POST'])
def register():
	form = RegisterForm(request.form)
	if request.method == 'POST' and form.validate():
		name = form.name.data
		email = form.email.data
		username = form.username.data
		password = sha256_crypt.encrypt(str(form.password.data))

		#create Cursor
		cur = mysql.connection.cursor()
		#excute query
		cur.execute("INSERT INTO users (name, email, username, password) VALUES(%s, %s, %s, %s)", (name, email, username, password))
		#commit to DB
		mysql.connection.commit()
		#close connection
		cur.close()

		flash('You are now registered', 'success')
		redirect(url_for('register'))

	return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST' :
		#Get form field
		username = request.form['username']
		password_candidate = request.form['password']
		
		#Create Cursor
		cur = mysql.connection.cursor()
		#Get User by username
		result = cur.execute("SELECT * FROM users WHERE email = %s", [username])

		if result > 0:
			#get stored hash
			data = cur.fetchone()
			password = data['password']
			#compare password
			if sha256_crypt.verify(password_candidate, password):
				#passed
				session['logged_in'] = True
				session['username'] = username

				flash('You are now logged in', 'success')
				return render_template('dashboard.html')
			else:
				error = 'Invalid Login'
				return render_template('login.html', error=error)
			#Close connection
			cur.close()
		else:
				app.logger.info('No User')

	return render_template('login.html')

#Check if user loggin
def is_logged_in(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if 'logged_in' in session :
			return f(*args, **kwargs)
		else:
			flash('Unauthorized Login', 'danger')
			return redirect(url_for('login'))
	return wrap


@app.route('/dashboard')
@is_logged_in
def dashboard():
	return render_template('dashboard.html')

@app.route('/logout')
def logout():
	session.clear()
	flash('You are now logged out', 'success')
	return redirect(url_for('login'))

if __name__ == '__main__':
	app.run(debug=True)


