from google.appengine.ext import db
class User(db.Model):
	'''database table of registered users'''
	user_id = db.StringProperty(required=True)
	pw_hash = db.StringProperty(required=True)
	email = db.StringProperty()