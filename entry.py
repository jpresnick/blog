import jinja2
import os
from google.appengine.ext import db
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
									autoescape=True)


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class Entry(db.Model):
	subject = db.StringProperty(required=True)
	content = db.TextProperty(required=True)
	created = db.DateTimeProperty(auto_now_add=True)
	last_modified = db.DateTimeProperty(auto_now=True)
	author = db.StringProperty(required=True)
	likes = db.IntegerProperty(default=0)
	liked_by = db.ListProperty(int)

	def render(self, cookie=None, comments="", like_unlike=""):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("post.html", p=self, 
										user_cookie=cookie, 
										comments=comments, 
										like_unlike=like_unlike)