import os
import re
import random
import hashlib
import hmac
from string import letters
import logging
import time
import webapp2
import jinja2
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'HkuhIU7iTY&*To87T(0'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


class MainPage(BlogHandler):
    def get(self):
        self.write('Hello!')
        self.redirect('/blog')


# user stuff
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# blog stuff

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    user_id = db.IntegerProperty(required=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


def comment_key(name='default'):
    return db.Key.from_path('comments', name)


class Comment(db.Model):
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    post_id = db.IntegerProperty(required=True)
    user_id = db.IntegerProperty(required=True)
    user_name = db.StringProperty(required=True)


def like_key(name='default'):
    return db.Key.from_path('likes', name)


class Like(db.Model):
    post_id = db.IntegerProperty(required=True)
    user_id = db.IntegerProperty(required=True)

    @classmethod
    def get_like(cls, user, post):
        l = Like.all().filter('user_id =', user).filter('post_id =',
                                                        post).get()
        return l


class BlogFront(BlogHandler):
    def get(self):
        if self.user:
            cookie = self.read_secure_cookie('user_id')
            user = User.by_id(int(cookie))
        else:
            cookie = ""

        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts=posts, user=cookie)


class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        comments = Comment.all().filter('post_id =',
                                        int(post_id)).order('-created')
        if self.user:
            uid = self.read_secure_cookie('user_id')
            likes = Like.get_like(int(uid), int(post_id))
            logging.info(likes)
            if post.user_id == int(uid):
                self.render("permalink.html", post=post, comments=comments,
                            mine="true")
            else:
                self.render("permalink.html", post=post, comments=comments,
                            likes=likes)
        else:
            self.render("permalink.html", post=post, comments=comments,
                        mine="false")

    def post(self, post_id):
        if not self.user:
            self.redirect('/blog')
        content = self.request.get('content')
        liked = self.request.get('liked')
        uid = self.read_secure_cookie('user_id')
        user = User.by_id(int(uid))
        if content:
            c = Comment(parent=comment_key(), content=content,
                        user_id=int(uid), user_name=user.name,
                        post_id=int(post_id))
            c.put()
            time.sleep(1)
            self.redirect('/blog/%s' % str(c.post_id))
        if liked:
            l = Like(parent=like_key(), user_id=int(uid), post_id=int(post_id))
            l.put()
            time.sleep(1)
            self.redirect('/blog/%s' % str(post_id))


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')
        uid = self.read_secure_cookie('user_id')

        if subject and content:
            p = Post(parent=blog_key(), subject=subject, content=content,
                     user_id=int(uid))
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content,
                        error=error)


class editComment(BlogHandler):
    def get(self, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=comment_key())
            comment = db.get(key)
            uid = self.read_secure_cookie('user_id')
            logging.info(comment)
            if comment.user_id != int(uid):
                error = "you are not authorized to edit this comment!"
                self.render("edit-comment.html", error=error)
            else:
                self.render("edit-comment.html", comment=comment)
        else:
            self.redirect("/login")

    def post(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id),
                               parent=comment_key())
        comment = db.get(key)
        delete = self.request.get('delete')
        if delete:
            comment.delete()
            time.sleep(1)
            self.redirect('/blog/%s' % comment.post_id)
        else:    
            comment.content = self.request.get('content')
            comment.put()
            content = self.request.get('content')
            time.sleep(1)
            self.redirect('/blog/%s' % comment.post_id)


class editPost(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            uid = self.read_secure_cookie('user_id')
            if post.user_id != int(uid):
                error = "you are not authorized to edit this Blog Post!"
                self.render("edit-post.html", error=error)
            else:
                self.render("edit-post.html", post=post)
        else:
            self.redirect("/login")

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        delete = self.request.get('delete')
        if delete:
            post.delete()
            time.sleep(1)
            self.redirect('/blog')
        else:    
            post.subject = self.request.get('subject')
            post.content = self.request.get('content')
            post.put()
            time.sleep(1)
            self.redirect('/blog/%s' % post.key().id())


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')


class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/comment/([0-9]+)', editComment),
                               ('/blog/edit/([0-9]+)', editPost),
                               ],
                              debug=True)
