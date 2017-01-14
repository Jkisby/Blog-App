from google.appengine.ext import db
import random
import hashlib
import hmac
import os
import jinja2
from string import letters


secret = 'HkuhIU7iTY&*To87T(0'


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


# methods for ensuring secure hashed password values.
# creates a secure value hashed with secret.
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


# checks if the value is secure by comparing with make_secure_val
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


# Creates salt
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


# Creates a hashed password with salt
def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


# ensures password vailidity using supplied salt.
def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


# User database model takes name, hash password, and email
class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

# returns a user from given ID
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

# returns user from given name
    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

# creates new user
    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

# returns a user from given name and password, if they exist
    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


# Post database model takes subject, content of post and user id.
class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    user_id = db.IntegerProperty(required=True)

    # renders a posts contents on post.html
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


def comment_key(name='default'):
    return db.Key.from_path('comments', name)


# Comment database model takes content of post and user/post id.
class Comment(db.Model):
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    post_id = db.IntegerProperty(required=True)
    user_id = db.IntegerProperty(required=True)
    user_name = db.StringProperty(required=True)


def like_key(name='default'):
    return db.Key.from_path('likes', name)


# Like database model to store users likes. Takes post and user id.
class Like(db.Model):
    post_id = db.IntegerProperty(required=True)
    user_id = db.IntegerProperty(required=True)

    @classmethod
    def get_like(cls, user, post):
        l = Like.all().filter('user_id =', user).filter('post_id =',
                                                        post)
        return l.get()
