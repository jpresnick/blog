import webapp2
import os
import jinja2
import re
import random
import string
import hashlib

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		params['user'] = self.user
		return render_str(template, **params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.request.cookies.get('user')
		self.user = uid and User.all().filter('user_id =', uid).get()

#displays 10 most recent blog posts on the main page ('/')
class MainPage(Handler):
	def get(self):
		entry = db.GqlQuery("SELECT * FROM Entry ORDER BY created DESC LIMIT 10")
		home_status = 'class=active'
		self.render("blog.html", entry = entry, home_status = home_status, user_cookie = self.request.cookies.get('user'))
	
	def post(self):
		entry = db.GqlQuery("SELECT * FROM Entry ORDER BY created DESC LIMIT 10")
		home_status = 'class=active'
		like = self.request.get("like")
		likes = 0
		if like:
			likes += 1
			post_id = self.request.get('id')
			key = db.Key.from_path('Entry', int(post_id))
			post = db.get(key)
			if not post:
				self.error(404)
				return
			post.likes = post.likes + 1
			likes = post.likes
			post.put()
		self.render("blog.html", entry = entry, home_status = home_status, user_cookie = self.request.cookies.get('user'), like = like)

#creates a user database
class User(db.Model):
	user_id = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()

#checks database to see if username exists
def new_username(username):
			u = User.all().filter('user_id =', username).get()
			if u:
				return False
			else: 
				return True

#checks to see if password is correct
def valid_pw(name, pw, h):
		    pw_hash, salt = h.split('|')
		    if hashlib.sha256(name + pw + salt).hexdigest() == pw_hash:
		        return True

#signup page allows users to create an account ('/signup')
class Signup(Handler):
	#gets user's registration criteria
	def get(self):
		signup_status = 'class=active'
		self.render("signup.html", signup_status = signup_status)

	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")
		verify = self.request.get("verify")
		email = self.request.get("email")

		USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
		def valid_username(username):
			return USER_RE.match(username)

		PASSWORD_RE = re.compile(r"^.{3,20}$")
		def valid_password(password):
			return PASSWORD_RE.match(password)

		EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
		def valid_email(email):
			return EMAIL_RE.match(email)

		def make_salt():
			return (''.join(random.choice(string.letters) for x in xrange(5)))

		def make_pw_hash(name, pw):
		    salt = make_salt()
		    h = hashlib.sha256(name + pw + salt).hexdigest()
		    return h + '|' + salt

		user_error = ""
		user_exists_error = ""
		password_error = ""
		verify_error = ""
		email_error = ""
		error = False

		if not valid_username(username):
			user_error = "That's not a valid username."
			error = True
		if not new_username(username):
		 	user_exists_error = "That user already exists."
		 	error = True
		if not valid_password(password):
			password_error = "That wasn't a valid password."
			error = True
		if password != verify:
			verify_error = "Your passwords didn't match."
			error = True
		if email:
			if not valid_email(email):
				email_error = "That's not a valid email."
				error = True
		if error == False:
			#add user to database
			h = User(pw_hash = make_pw_hash(username, password), user_id = username, email = email)
			h.put()
			#set user cookie
			self.response.headers.add_header('Set-Cookie', 'user=%s; Path=/' % str(h.user_id))
			self.redirect("/welcome")	
		else:
			self.render('signup.html', username = username, email = email, 
									user_error = user_error, user_exists_error = user_exists_error, password_error = password_error, 
									verify_error = verify_error, email_error = email_error)

class Login(Handler):
	def get(self):
		login_status = 'class=active'
		self.render("login.html", login_status = login_status)

	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")

		user_exists_error = ""
		password_error = ""
		error = False

		if new_username(username):
			user_exists_error = "That username does not exist"
			error = True

		u = User.all().filter('user_id =', username).get()
		if not valid_pw(username, password, u.pw_hash):
			password_error = "Incorrect password"
			error = True

		if error:
			self.render('login.html', username = username, user_exists_error = user_exists_error, 
									password_error = password_error)
		else:
			#set user cookie and redirect to welcome page
			self.response.headers.add_header('Set-Cookie', 'user=%s; Path=/' % str(u.user_id))
			#self.redirect("/welcome")	
			self.redirect("/welcome")

class Logout(Handler):
	def get(self):
		#clears cookie
		self.response.headers.add_header('Set-Cookie', 'user=%s; Path=/' % "")
		#self.redirect("/login")	
		self.redirect("/signup")

def get_cookie(self, name):
	cookie = self.request.cookies.get(name)
	return self.cookie

class WelcomeHandler(Handler):
	def get(self):
		user_info = self.request.cookies.get('user')	
		self.render("welcome.html", username = user_info)

class Entry(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)
	author = db.StringProperty(required = True)
	likes = db.IntegerProperty()
	comments = db.IntegerProperty()

	def render(self, cookie=None, likes=0):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("post.html", p = self, user_cookie = cookie)

class PermalinkHandler(Handler):
	def get(self, post_id):
		key = db.Key.from_path("Entry", int(post_id))
		post = db.get(key)
		if not post:
			self.error(404)
			return
		
		self.render("permalink.html", post = post)

class NewPostHandler(Handler):
	def get(self):
		newpost_status = 'class=active'
		self.render("newpost.html", newpost_status = newpost_status)
	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")
		author = self.request.cookies.get('user')

		if subject and content:
			e = Entry(subject = subject, content = content, author = author, likes = 0)
			e.put()
			self.redirect('/' + str(e.key().id()))

		else:
			error = "You must submit a subject and some content."
			self.render("newpost.html", subject = subject, content = content, error = error)

class EditPost(Handler):
	def get(self):
		post_id = self.request.get("id")
		key = db.Key.from_path("Entry", int(post_id))
		post = db.get(key)
		if not post:
			self.error(404)
			return

		self.render("editpost.html", post = post)

	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")
		post_id = self.request.get("id")
		key = db.Key.from_path("Entry", int(post_id))

		delete = self.request.get("delete")
		if delete:
			post = db.get(key)
			post.delete()
			self.redirect('/confirm-delete')

		elif subject and content:
			post = db.get(key)
			post.subject = subject
			post.content = content
			post.put()
			self.redirect('/' + str(post.key().id()))

		else: 
			error = "You must submit a subject and some content."
			self.render("newpost.html", subject = subject, content = content, error = error)

class ConfirmDeleteHandler(Handler):
	def get(self):
		self.render("confirm-delete.html")

app = webapp2.WSGIApplication([('/', MainPage),
								("/welcome", WelcomeHandler),
								("/signup", Signup),
								('/login', Login),
								('/blog/?', MainPage),
								('/newpost', NewPostHandler),
								('/([0-9]+)', PermalinkHandler),
								('/logout', Logout),
								('/editpost/?', EditPost),
								('/confirm-delete', ConfirmDeleteHandler),
								],
    							debug=True)