import os
import re
import logging
import time
import webapp2
import jinja2
from google.appengine.ext import db
from database import *

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


# Main handler with placeholder methods
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # sets a cookie with given parameters
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    # reads a cookie and checks validity
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # create a cookie for user on login
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    # remove cookie value on logout
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


# main page redirects to blog
class MainPage(BlogHandler):
    def get(self):
        self.write('Hello!')
        self.redirect('/blog')


# renders main blog page. Checks for user to allow creating posts.
class BlogFront(BlogHandler):
    def get(self):
        if self.user:
            cookie = self.read_secure_cookie('user_id')
            user = User.by_id(int(cookie))
        else:
            cookie = ""

        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts=posts, user=cookie)


# renders individual post pages
class PostPage(BlogHandler):
    def get(self, post_id):
        # find post and comments from database
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return self.render('error.html')
        comments = Comment.all().filter('post_id =',
                                        int(post_id)).order('-created')

        # checks if user logged in/post belongs to user
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

    # post method, checks like button and comment forms.
    def post(self, post_id):
        if not self.user:
            return self.redirect('/login')
        content = self.request.get('content')
        liked = self.request.get('liked')
        uid = self.read_secure_cookie('user_id')
        user = User.by_id(int(uid))
        if content:
            # add comment if user logged in
            c = Comment(parent=comment_key(), content=content,
                        user_id=int(uid), user_name=user.name,
                        post_id=int(post_id))
            c.put()
            time.sleep(1)
            return self.redirect('/blog/%s' % str(c.post_id))
        if liked:
            # check if likes exist already/post belongs to user before liking
            likes = Like.get_like(int(uid), int(post_id))
            if int(uid) != int(post_id) and not likes:
                l = Like(parent=like_key(), user_id=int(uid),
                         post_id=int(post_id))
                l.put()
                time.sleep(1)
                return self.redirect('/blog/%s' % str(post_id))
            else:
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                post = db.get(key)
                comments = Comment.all().filter('post_id =',
                                                int(post_id)).order('-created')
                error = "Can't like own post or like a post more than once!"
                return self.render("permalink.html", post=post,
                                   comments=comments, error=error)


# renders new post page, redirects to login if not logged in
class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')
        uid = self.read_secure_cookie('user_id')

        # check subject and content both entered
        if subject and content:
            p = Post(parent=blog_key(), subject=subject, content=content,
                     user_id=int(uid))
            p.put()
            return self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content,
                        error=error)


# renders edit comment page for a comment
class editComment(BlogHandler):
    def get(self, comment_id):
        if self.user:
            # ensure user is authorized to view this page
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

    # post method checks user is authorized to edit comment
    def post(self, comment_id):
        if not self.user:
            return self.redirect('/login')

        uid = self.read_secure_cookie('user_id')
        key = db.Key.from_path('Comment', int(comment_id),
                               parent=comment_key())
        comment = db.get(key)
        if comment.user_id != int(uid):
            alert("You are not authorized to edit this comment!")
            return self.redirect('/blog')

        delete = self.request.get('delete')
        if delete:
            comment.delete()
            time.sleep(1)
            return self.redirect('/blog/%s' % comment.post_id)
        else:
            comment.content = self.request.get('content')
            comment.put()
            content = self.request.get('content')
            time.sleep(1)
            return self.redirect('/blog/%s' % comment.post_id)


# renders page to edit a post
class editPost(BlogHandler):
    def get(self, post_id):
        if self.user:
            # check user is authorized to view this page
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

    # post method checks user is authorized to edit post
    def post(self, post_id):
        if not self.user:
            return self.redirect('/login')

        uid = self.read_secure_cookie('user_id')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post.user_id != int(uid):
            return self.redirect('/blog')

        delete = self.request.get('delete')
        if delete:
            post.delete()
            time.sleep(1)
            return self.redirect('/blog')
        else:
            post.subject = self.request.get('subject')
            post.content = self.request.get('content')
            post.put()
            time.sleep(1)
            return self.redirect('/blog/%s' % post.key().id())


# regex methods to ensure valid username/password/email
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


# signup handler renders signup page
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

        # add errors if exist in signup process
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


# login handler renders login page
class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        # ensure user details are correct
        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


# logout handler
class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')


# 404 error page
class NotFoundPageHandler(BlogHandler):
    def get(self):
        self.error(404)
        self.render('error.html')


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/comment/([0-9]+)', editComment),
                               ('/blog/edit/([0-9]+)', editPost),
                               ('/.*', NotFoundPageHandler)
                               ],
                              debug=True)
