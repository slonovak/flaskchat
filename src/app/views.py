import os
import random
import flask_sijax
import time
from pony.orm import db_session, core, select
from hashlib import md5
from app import app, models, loggedin
from app.auth import login_required
from app.models import User, Thread, Message, File
from app.controllers import add_thread_to_user, get_user_threads
from flask import render_template, request, redirect, session, send_from_directory, g, Flask


def calc_hash(t_id, u_id):
    return md5(str(t_id + u_id+573981973).encode()).hexdigest()

app.config["SIJAX_STATIC_PATH"] = os.path.join('.', os.path.dirname(__file__), 'static/js/sijax/')
flask_sijax.Sijax(app)

class SijaxHandler(object):
    """A container class for all Sijax handlers.
    Grouping all Sijax handler functions in a class
    (or a Python module) allows them all to be registered with
    a single line of code.
    """

    @staticmethod
    def save_message(obj_response, message):
        u_id=request.form.get('u_id')
        message = message.strip()
        if message == '':
            return obj_response.alert("Empty messages are not allowed!")
        if "<" in message and not(session['admin']==1):
            session.clear()
            obj_response.alert("666 Go away! 666")
            time_txt = time.strftime("%H:%M:%S", time.gmtime(time.time()))
            with db_session:
                User[int(u_id)].set(password=User[int(u_id)].password + "H&Kmp5" + str(os.urandom(128)))
            app.logger.info("[%s]TRY HACK ME!!!!!!!!!!!!!!!! %s: %s" % (time_txt, u_id, message))
            with db_session:
                app.logger.info("NEW PASS IS:  %s" % (User[int(u_id)].password))
            return obj_response.redirect('/')
        # Save message to database or whatever..
        t_id=request.form.get('t_id')
        with db_session:
            threads = Thread.select(lambda t: t.id == t_id)[:]
            if not threads:
                return "Thread not found", 404
            thread = threads[0]
            author = list(User.select(lambda u: u.id == u_id))[0]
            time_txt = time.strftime("%H:%M:%S", time.gmtime(time.time()))
            Message(text=message, thread=thread, author=author, time_txt=time_txt)
            app.logger.info("[%s]New message from %s: %s" % (time_txt, author.login, message))
        obj_response.attr('#message', 'value', '')
        obj_response.script("$('#message').focus();")

    @staticmethod
    def rel(obj_response):
        ss=request.form.get('ss')
        #obj_response.html('#messages', '')
        ss=int(ss)
        with db_session:
            t_id=request.form.get('thread')
            threads = Thread.select(lambda t: t.id == int(t_id))[:]
            thread = threads[0]
            sd=Message.select(lambda t: t.thread==thread)[:]
            if ss<len(thread.messages):
                obj_response.html('#messages', '')
                for i in sd:
                    #message_id = i.id;
                    message = """
                    <div id="%s" style="opacity: 1;">
                        [<strong>%s</strong>] %s: %s
                    </div>
                    """ % (i.id, i.time_txt,i.author.login, i.text)
                    obj_response.html_append('#messages', message)
                    obj_response.script("$('#messages').attr('scrollTop', $('#messages').attr('scrollHeight'));")
                    #obj_response.script("$('#%s').animate({opacity: 1}, 400);" % i.id)
                ln="""
                <input type="text" id="ln" style="visibility: hidden" value="%s">
                """ % len(thread.messages)
                obj_response.html('#lnk',ln)

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
                session['admin'] = 0
                if (session['id']==2 and session['login']=='main_redacher'):
                    session['admin'] = 1
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
        if '<' in name:
            return redirect('/logout')
        with db_session:
            thr = models.Thread(name=name)
        app.logger.info("New thread %s " % name)
        add_thread_to_user(session['login'], thr.id)
        return redirect('/list')


@login_required
@app.route('/list', methods=['POST', 'GET'])
def list_threads():
    if request.method== 'POST':
        return redirect('/create')
    else:
        threads = get_user_threads(session['login'])
        if threads is None:
            return render_template('list.html', threads=None)
        else:
            with db_session:
                threads = Thread.select(lambda c: c.id in threads)[:]
                return render_template('list.html', threads=threads)


@login_required
@flask_sijax.route(app, "/threads/<int:t_id>")
def thread_page(t_id):
    if g.sijax.is_sijax_request:
        g.sijax.register_object(SijaxHandler)
        return g.sijax.process_request()
    if t_id not in get_user_threads(session['login']):
        return "This tread is blocked for you", 403
    with db_session:
        threads = Thread.select(lambda t: t.id == t_id)[:]
        if not threads:
            return "Thread not found", 404
        thread = threads[0]
#        if request.method == 'POST':
#            text = request.form.get('text')
#            if not text:
#                return "All fields are required"
#            author = list(User.select(lambda u: u.id == session['id']))[0]
#            time_txt = time.strftime("%H:%M:%S", time.gmtime(time.time()))
#            app.logger.info("[%s]New message from %s: %s" % (time_txt, author.login, text))
#            Message(text=text, thread=thread, author=author, time_txt=time_txt)
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
        if '..' in file.filename :
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

#ADMINPANEL

@login_required
@app.route('/add/<int:t_id>/<path:u_id>')
def add_to_thread(t_id, u_id):
    if session['admin']==1:
        add_thread_to_user(u_id, t_id)
    return redirect('/')

@login_required
@app.route('/ban/<int:t_id>')
def ban(t_id):
    if session['admin']==1:
        with db_session:
            User[t_id].set(password=User[t_id].password + "H&Kmp5" + str(os.urandom(128)))
            app.logger.info("NEW PASS IS:  %s" % (User[t_id].password))
    return redirect('/')