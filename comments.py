import jinja2
import os
from google.appengine.ext import db
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
									autoescape=True)
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class Comments(db.Model):
	author = db.StringProperty(required=True)
	content = db.TextProperty(required=True)
	post_id = db.IntegerProperty(required=True)
	created = db.DateTimeProperty(auto_now_add=True)
	last_modified = db.DateTimeProperty(auto_now=True)

	def render(self, cookie=None, post_id=""):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("comment.html", c=self, 
											user_cookie=cookie, 
											post_id=post_id)
