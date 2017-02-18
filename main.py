import webapp2
import os
import jinja2
import re
import random
import string
import hashlib
import time

from user import User
from comments import Comments
from entry import Entry
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
									autoescape=True)


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


# displays 10 most recent blog posts on the main page ('/')
class MainPage(Handler):
	'''
	Renders the main page of the blog. 
	This page contains the 10 most recent blog posts
	'''
	def get(self):
		entry = db.GqlQuery("SELECT * FROM Entry ORDER BY created DESC LIMIT 10")
		home_status = 'class=active'
		comments = db.GqlQuery("SELECT * FROM Comments ORDER BY created DESC")
		self.render("blog.html", entry=entry,
								comments=comments,
								home_status=home_status,
								user_cookie=self.request.cookies.get('user'),
								like_unlike="like")

	def post(self):
		entry = db.GqlQuery("SELECT * FROM Entry ORDER BY created DESC LIMIT 10")
		home_status = 'class=active'
		if not self.user:
			return self.redirect('/login')

		post_id = self.request.get('postID')
		comment = self.request.get("comment")
		clicked_like = self.request.get("clicked_like")
		author = self.request.cookies.get('user')
		post = Entry.get_by_id(int(post_id))
		like_unlike = "like"
		if not post:
			self.error(404)
			return self.redirect('/not_found')

		# allows the user to like/unlike posts, but not their own.
		if clicked_like:
			already_liked = False
			for user in post.liked_by:
				if user == self.user.key().id():
					already_liked = True
			if already_liked:
				post.likes = post.likes - 1
				post.liked_by.remove(self.user.key().id())
				post.put()
			else:
				post.likes += 1
				post.liked_by.append(self.user.key().id())
				post.put()
				like_unlike = "unlike"

		# adds a new comment
		if comment:
			c = Comments(author=author, content=comment, post_id=int(post_id))
			c.put()

		# fetches existing comments
		comments = db.GqlQuery("SELECT * FROM Comments ORDER BY created DESC")

		time.sleep(0.2)
		self.render("blog.html", entry=entry, 
								comments=comments, 
								home_status=home_status,
								user_cookie=self.request.cookies.get('user'), 
								like_unlike=like_unlike)


# creates a user database
# class User(db.Model):
# 	'''database table of registered users'''
# 	user_id = db.StringProperty(required=True)
# 	pw_hash = db.StringProperty(required=True)
# 	email = db.StringProperty()


# checks database to see if username exists
def new_username(username):
	'''
	checks database to see if username exists
 	Args:
        arg1 (data type: str): username you are checking
    Returns:
        True or False
	'''
	u = User.all().filter('user_id =', username).get()
	if u:
		return False
	else: 
		return True


# checks to see if password is correct
def valid_pw(name, pw, h):
	'''
	checks database to see if password is correct
 	Args:
        arg1 (data type: str): username you entered
        arg2 (data type: str): password you entered
        arg3 (data type: int): password hash value from database
    Returns:
        True or False
	'''
	pw_hash, salt = h.split('|')
	if hashlib.sha256(name + pw + salt).hexdigest() == pw_hash:
		return True


# signup page allows users to create an account ('/signup')
class Signup(Handler):
	'''signup page allows users to create an account ('/signup')'''
	# gets user's registration criteria
	def get(self):
		signup_status = 'class=active'
		self.render("signup.html", signup_status=signup_status)

	def post(self):
		# gets inputs and checks that they are valid
		username = self.request.get("username")
		password = self.request.get("password")
		verify = self.request.get("verify")
		email = self.request.get("email")

		USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
		PASSWORD_RE = re.compile(r"^.{3,20}$")
		EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

		def valid_username(username):
			'''
			checks if username entered is valid
			Args:
        		arg1 (data type: str): username you entered
			'''

			return USER_RE.match(username)

		def valid_password(password):
			'''
			checks if password entered is valid
			Args:
        		arg1 (data type: str): password you entered
			'''
			return PASSWORD_RE.match(password)

		def valid_email(email):
			'''
			checks if email entered is valid
			Args:
        		arg1 (data type: str): email you entered
			'''
			return EMAIL_RE.match(email)

		def make_salt():
			'''makes 5 digit random salt value'''
			return (''.join(random.choice(string.letters) for x in xrange(5)))

		def make_pw_hash(name, pw):
			'''makes password hash with username and salt'''
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
		if not error:
			# add user to database
			h = User(pw_hash=make_pw_hash(username, password), 
						user_id=username, email=email)
			h.put()
			# set user cookie
			self.response.headers.add_header('Set-Cookie', 
												'user=%s; Path=/' % str(h.user_id))
			time.sleep(0.2)
			time.sleep(0.2)
			self.redirect("/welcome")	
		else:
			self.render('signup.html', username=username, email=email, 
										user_error=user_error, 
										user_exists_error=user_exists_error, 
										password_error=password_error, 
										verify_error=verify_error, 
										email_error=email_error)


class Login(Handler):
	'''user login page'''
	def get(self):
		login_status = 'class=active'
		self.render("login.html", login_status=login_status)

	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")

		user_exists_error = ""
		password_error = ""
		error = False

		# check for valid login info
		if new_username(username):
			user_exists_error = "That username does not exist"
			error = True

		u = User.all().filter('user_id =', username).get()
		if u:
			if not valid_pw(username, password, u.pw_hash):
				password_error = "Incorrect password"
				error = True

		if error:
			self.render('login.html', username=username, 
										user_exists_error=user_exists_error, 
										password_error=password_error)
		else:
			# set user cookie and redirect to welcome page
			self.response.headers.add_header('Set-Cookie', 
								'user=%s; Path=/' % str(u.user_id))
			self.redirect("/welcome")


class Logout(Handler):
	'''erases user cookie, to log user out'''
	def get(self):
		# clears cookie
		self.response.headers.add_header('Set-Cookie', 'user=%s; Path=/' % "")	
		self.redirect("/login")


# user is redirected here after login or signup
class WelcomeHandler(Handler):
	'''Welcome page. User is redirected here after login or signup'''
	def get(self):
		user_info = self.request.cookies.get('user')	
		self.render("welcome.html", username=user_info)


# table of blog posts
# class Entry(db.Model):
# 	subject = db.StringProperty(required=True)
# 	content = db.TextProperty(required=True)
# 	created = db.DateTimeProperty(auto_now_add=True)
# 	last_modified = db.DateTimeProperty(auto_now=True)
# 	author = db.StringProperty(required=True)
# 	likes = db.IntegerProperty(default=0)
# 	liked_by = db.ListProperty(int)

# 	def render(self, cookie=None, comments="", like_unlike=""):
# 		self._render_text = self.content.replace('\n', '<br>')
# 		return render_str("post.html", p=self, 
# 										user_cookie=cookie, 
# 										comments=comments, 
# 										like_unlike=like_unlike)


# table of comments
# class Comments(db.Model):
# 	author = db.StringProperty(required=True)
# 	content = db.TextProperty(required=True)
# 	post_id = db.IntegerProperty(required=True)
# 	created = db.DateTimeProperty(auto_now_add=True)
# 	last_modified = db.DateTimeProperty(auto_now=True)

# 	def render(self, cookie=None, post_id=""):
# 		self._render_text = self.content.replace('\n', '<br>')
# 		return render_str("comment.html", c=self, 
# 											user_cookie=cookie, 
# 											post_id=post_id)


# page to display an individual blog post
class PermalinkHandler(Handler):
	'''page to display an individual blog post'''
	def get(self, post_id):
		key = db.Key.from_path("Entry", int(post_id))
		post = db.get(key)
		if not post:
			self.error(404)
			return self.redirect('/not_found')
		
		self.render("permalink.html", post=post, 
										user_cookie=self.request.cookies.get('user'))


# allows user to submit a new post if they are logged in
class NewPostHandler(Handler):
	'''allows user to submit a new post if they are logged in'''
	def get(self):
		newpost_status = 'class=active'
		self.render("newpost.html", newpost_status=newpost_status)

	def post(self):
		if not self.user:
			return self.redirect('/login')

		subject = self.request.get("subject")
		content = self.request.get("content")
		author = self.request.cookies.get('user')

		if subject and content:
			e = Entry(subject=subject, content=content, author=author)
			e.put()
			self.redirect('/' + str(e.key().id()))

		else:
			error = "You must submit a subject and some content."
			self.render("newpost.html", subject=subject, 
											content=content, 
											error=error)


# allows user to edit and delete their own posts
class EditPost(Handler):
	'''allows user to edit and delete their own posts'''
	def get(self):
		post_id = self.request.get("id")
		key = db.Key.from_path("Entry", int(post_id))
		post = db.get(key)
		if not post:
			self.error(404)
			return self.redirect('/not_found')

		if self.request.cookies.get('user') == post.author:
			self.render("editpost.html", subject=post.subject, content=post.content)
		else:
			self.redirect('/editerror')

	def post(self):
		if not self.user:
			return self.redirect('/login')

		subject = self.request.get("subject")
		content = self.request.get("content")
		post_id = self.request.get("id")
		key = db.Key.from_path("Entry", int(post_id))
		post = db.get(key)
		if not post:
			self.error(404)
			return self.redirect('/not_found')

		if self.request.cookies.get('user') == post.author:
			delete = self.request.get("delete")
			cancel = self.request.get("cancel")
			if delete:
				post.delete()
				self.redirect('/confirm-delete/?id=post.key().id()')

			elif cancel:
				self.redirect('/')

			elif subject and content:
				post.subject = subject
				post.content = content
				post.put()
				self.redirect('/' + str(post.key().id()))

			else: 
				error = "You must submit a subject and some content."
				self.render("editpost.html", subject=subject, content=content, error=error)
		else:
			self.redirect("/editerror")


# this page allows a user to edit or delete one of their comments
class EditCommentHandler(Handler):
	'''this page allows a user to edit or delete one of their comments'''
	def get(self):
		if not self.user:
			return self.redirect('/login')

		comment_id = self.request.get("id")
		key = db.Key.from_path("Comments", int(comment_id))
		comment = db.get(key)

		if not comment:
			self.error(404)
			return self.redirect('/not_found')

		if self.request.cookies.get('user') == comment.author:
			self.render("edit-comment.html", content=comment.content)
		else:
			self.redirect('/editerror')

	def post(self):
		if not self.user:
			return self.redirect('/login')

		content = self.request.get('content')
		comment_id = self.request.get("id")
		key = db.Key.from_path("Comments", int(comment_id))
		comment = db.get(key)

		if self.request.cookies.get('user') == comment.author:
			delete = self.request.get("delete")
			cancel = self.request.get("cancel")
			if delete:
				comment.delete()
				self.redirect('/confirm-delete/?id=comment.key().id()')

			elif cancel:
				self.redirect('/')

			elif content:
				comment.content = content
				comment.put()
				time.sleep(0.2)
				self.redirect('/')
			
			else: 
				error = "Your comment is blank."
				self.render("edit-comment.html", 
							content=content, 
							error=error)
		else:
			self.redirect('/editerror')


# user redirected here if they successfully delete one of their posts or comments
class ConfirmDeleteHandler(Handler):
	'''
	user redirected here if they successfully delete one of their 
	posts or comments
	'''
	def get(self):
		delete_type = self.request.get('id')
		self.render("confirm-delete.html", type=delete_type)


class EditErrorHandler(Handler):
	'''displays an error if user tries to edit a comment/post that is
	not theirs
	'''
	def get(self):
		self.render("editerror.html")

class NotFoundHandler(Handler):
	'''displays an error page if the page cannot be found'''
	def get(self):
		self.render("not_found.html")

app = webapp2.WSGIApplication([('/', MainPage),
								("/welcome", WelcomeHandler),
								("/signup", Signup),
								('/login', Login),
								('/blog/?', MainPage),
								('/newpost', NewPostHandler),
								('/([0-9]+)', PermalinkHandler),
								('/logout', Logout),
								('/editpost/?', EditPost),
								('/confirm-delete/?', ConfirmDeleteHandler),
								('/edit-comment/?', EditCommentHandler),
								('/editerror', EditErrorHandler),
								('/not_found', NotFoundHandler),
								],
    							debug=True)