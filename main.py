import webapp2
import os
import jinja2
import re

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__))
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		return render_str(template, **params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

class MainPage(Handler):
	def get(self):
		entry = db.GqlQuery("SELECT * FROM Entry ORDER BY created DESC LIMIT 10")
		self.render("blog.html", entry = entry)

class Entry(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("blog.html", p = self)

class NewPostHandler(Handler):
	def get(self):
		self.render("newpost.html")
	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")

		if subject and content:
			e = Entry(subject = subject, content = content)
			e.put()
			self.redirect('/blog/%s' % str(e.key().id()))

		else:
			error = "You must submit a subject and some content."
			self.render("newpost.html", subject = subject, content = content, error = error)
		
class PermalinkHandler(Handler):
	def get(self, post_id):
		key = db.Key.from_path("Post", int(post_id))
		post = db.get(key)
		if not post:
			self.error(404)
			return
		
		self.render("permalink.html", post = post)


app = webapp2.WSGIApplication([('/', MainPage),
								('/blog/?', MainPage),
								('/blog/newpost', NewPostHandler),
								(r'/blog/([0-9]+)', PermalinkHandler),
								],
    							debug=True)