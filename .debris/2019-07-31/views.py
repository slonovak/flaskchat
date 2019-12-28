import os
import random
import flask_sijax
from pony.orm import db_session, core, select
from hashlib import md5
from app import app, models, loggedin
from app.auth import login_required
from app.models import User, Thread, Message, File
from app.controllers import add_thread_to_user, get_user_threads
from flask import render_template, request, redirect, session, send_from_directory


def calc_hash(t_id, u_id):
    return md5(str(t_id + u_id+9675438).encode()).hexdigest()

class SijaxHandler(object):
    """A container class for all Sijax handlers.
    Grouping all Sijax handler functions in a class
    (or a Python module) allows them all to be registered with
    a single line of code.
    """

    @staticmethod
    def save_message(obj_response, message):

        message = message.strip()
        if message == '':
            return obj_response.alert("Empty messages are not allowed!")

        # Save message to database or whatever..

        import time, hashlib
        time_txt = time.strftime("%H:%M:%S", time.gmtime(time.time()))
        message_id = 'message_%s' % hashlib.sha256(time_txt.encode("utf-8")).hexdigest()

        message = """
        <div id="%s" style="opacity: 0;">
            [<strong>%s</strong>] %s
        </div>
        """ % (message_id, time_txt, message)

        # Add message to the end of the container
        obj_response.html_append('#messages', message)

        # Clear the textbox and give it focus in case it has lost it
        obj_response.attr('#message', 'value', '')
        obj_response.script("$('#message').focus();")

        # Scroll down the messages area
        obj_response.script("$('#messages').attr('scrollTop', $('#messages').attr('scrollHeight'));")

        # Make the new message appear in 400ms
        obj_response.script("$('#%s').animate({opacity: 1}, 400);" % message_id)


    @staticmethod
    def clear_messages(obj_response):

        # Delete all messages from the database

        # Clear the messages container
        obj_response.html('#messages', '')

        # Clear the textbox
        obj_response.attr('#message', 'value', '')

        # Ensure the texbox has focus
        obj_response.script("$('#message').focus();")

@app.route('/login', methods=['POST', 'GET'])
def login_page():
    if request.method == 'GET':
        return render_template('login.html')
    login = request.form.get('login')
    password = request.form.get('password')
    if login and password:
        with db_session:
            user = select(u for u in User if u.login == login and u.password == password)[:]
            if user:
                user = user[0]
                session['id'] = user.id
                session['login'] = user.login
                return redirect('/')
            else:
                return redirect('/login')
    else:
        return "All fields are required"


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'GET':
        return render_template('register.html')

    login = request.form.get('login')
    password = request.form.get('password')
    if login and password:
        try:
            with db_session:
                models.User(login=login, password=password)
            app.logger.info("New user %s" % login)
        except core.TransactionIntegrityError:
            return "Login already exists"
        return redirect('/login')
    return "All fields are required"


@app.route('/')
def index():
    return render_template('index.html')


@login_required
@app.route('/create', methods=['POST', 'GET'])
def create_thread():
    if request.method == 'GET':
        return render_template('create.html')
    else:
        name = request.form.get('name')
        if not name:
            return "All fields are required"
        with db_session:
            thr = models.Thread(name=name)
        app.logger.info("New thread %s " % name)
        add_thread_to_user(session['login'], thr.id)
        return redirect('/list')


@login_required
@app.route('/list')
def list_threads():
    threads = get_user_threads(session['login'])
    if threads is None:
        return render_template('list.html', threads=None)
    else:
        with db_session:
            threads = Thread.select(lambda c: c.id in threads)[:]
            return render_template('list.html', threads=threads)


@login_required
@app.route('/threads/<int:t_id>', methods=['POST', 'GET'])
def thread_page(t_id):
    if t_id not in get_user_threads(session['login']):
        return "This tread is blocked for you", 403

    with db_session:
        threads = Thread.select(lambda t: t.id == t_id)[:]
        if not threads:
            return "Thread not found", 404
        thread = threads[0]
        if request.method == 'POST':
            text = request.form.get('text')
            if not text:
                return "All fields are required"
            author = list(User.select(lambda u: u.id == session['id']))[0]
            app.logger.info("New message from %s: %s" % (author.login, text))
            Message(text=text, thread=thread, author=author)
        somebody = Message.select(lambda t: t.thread==thread)[:]
        u_id = session['id']
        hash = calc_hash(t_id, u_id)
        return render_template('thread_page.html', thread=thread, u_id=u_id, t_id=t_id, hash=hash, somebody=somebody)


@login_required
@app.route('/upload', methods=['POST', 'GET'])
def thread_upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
        if '../' in file.filename :
            return redirect(request.url)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))
        with db_session:
            author = list(User.select(lambda u: u.id == session['id']))[0]
            File(filename=file.filename, user=author)
        return redirect('/')
    return render_template('upload.html')


@login_required
@app.route('/uploads')
def uploads():
    with db_session:
        files = File.select(lambda f: f.user.id == session['id'])[:]
        return render_template('uploads.html', files=files)


@login_required
@app.route('/uploads/<path:filename>')
def send_upload(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@login_required
@app.route('/find/<int:t_id>/<int:u_id>/<hash>')
def find_thread(t_id, u_id, hash):
    calced = calc_hash(t_id, u_id)
    if hash == calced:
        add_thread_to_user(session['login'], t_id)
        return redirect('/list')
    else:
        return "Bad hash"

@login_required
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@login_required
@flask_sijax.route(app, "/chat")
def index():
    if g.sijax.is_sijax_request:
        # The request looks like a valid Sijax request
        # Let's register the handlers and tell Sijax to process it
        g.sijax.register_object(SijaxHandler)
        return g.sijax.process_request()

    return render_template('chat.html')
