#!/usr/local/bin/python3

from flask import Flask,render_template,request,make_response,redirect,url_for,flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
import os, httpx, asyncio, sys, logging, random, string,shutil
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

CONFIG_DIR = os.path.join("/etc/",os.path.basename(__file__).split(".py")[0])
DB_FILE = os.path.join(CONFIG_DIR,os.path.basename(__file__).split(".py")[0]+".db")
TELEGRAM_TOKEN = TELEGRAM_CHATID = LOG_FILE = CACHE_FOLDER_BEGIN_WITH = ""
application = Flask(__name__)
application.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + DB_FILE
application.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
application.config['PERMANENT_SESSION_LIFETIME'] = 28800
db = SQLAlchemy(application)
login_manager = LoginManager(application)
login_manager.login_view = "login"

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    realname = db.Column(db.String(80), nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    permissions = db.Column(db.Text,default="*")
    created = db.Column(db.DateTime,default=datetime.now)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    telegramChat = db.Column(db.String(16), nullable=True)
    telegramToken = db.Column(db.String(64), nullable=True)
    logFile = db.Column(db.String(512), nullable=True)
    cryptKey = db.Column(db.String(64), nullable=True)
    cacheFolderBeginWith = db.Column(db.String(64), nullable=True)

class CachePath(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cacheName = db.Column(db.String(32), nullable=False, unique=True)
    cachePath = db.Column(db.String(512), nullable=False, unique=True)
    created = db.Column(db.DateTime,default=datetime.now)

def generate_default_config():   
    if not os.path.exists(DB_FILE):
        length = 64
        characters = string.ascii_letters + string.digits
        cookie_salt = ''.join(random.choice(characters) for _ in range(length))
        default_settings = Settings(id=1, telegramChat="", telegramToken="", logFile="/tmp/nginx-cache-log.txt", cryptKey=cookie_salt,cacheFolderBeginWith="/tmp")
        try:
            os.mkdir(CONFIG_DIR)
            db.create_all()
            db.session.add(default_settings)
            db.session.commit()
            print(f"First launch. Default database created in {DB_FILE}. You need to add telegram ChatID and Token if you want to get notifications")
        except Exception as msg:
            print(f"Generate-default-config error: {msg}")
            quit(1)

def set_telegramChat(tgChat):
    t = Settings(id=1,telegramChat=tgChat.strip())
    db.session.merge(t)
    db.session.commit()
    load_config()
    print("Telegram ChatID added successfully")
    try:
        logging.info(f"Telegram ChatID updated successfully!")
    except Exception as err:
        pass

def set_telegramToken(tgToken):
    t = Settings(id=1,telegramToken=tgToken)
    db.session.merge(t)
    db.session.commit()
    load_config()
    print("Telegram Token added successfully")
    try:
        logging.info(f"Telegram Token updated successfully!")
    except Exception as err:
        pass

def set_logpath(logpath):
    t = Settings(id=1,logFile=logpath)
    db.session.merge(t)
    db.session.commit()
    load_config()
    updated = db.session.get(Settings, 1)
    print(f"logPath updated successfully. New log path: \"{updated.logFile}\"")
    try:
        logging.info(f"logPath updated to \"{updated.logFile}\"")
    except Exception as err:
        pass
        
def register_user(username,password,realname):
    try:
        if User.query.filter_by(username=username).first():
            print(f"User \"{username}\" creation error - already exists!")
            logging.error(f"User \"{username}\" creation error - already exists!")
        else:
            new_user = User(
                username=username,
                password_hash=generate_password_hash(password),
                realname=realname,
                permissions = "*"
            )
            db.session.add(new_user)
            db.session.commit()
            load_config()
            print(f"New user \"{username}\" - \"{realname}\" created successfully!")
            logging.info(f"New user \"{username}\" - \"{realname}\" created successfully!")
    except Exception as err:
        logging.error(f"User \"{username}\" - \"{realname}\" creation error: {err}")
        print(f"User \"{username}\" - \"{realname}\" creation error: {err}")

def update_user(username,password):
    try:
        user = User.query.filter_by(username=username).first()
        if user:
            d = User(id=user.id,password_hash=generate_password_hash(password))
            db.session.merge(d)
            db.session.commit()
            load_config()
            print(f"Password for user \"{user.username}\" updated successfully!")
            logging.info(f"Password for user \"{user.username}\" updated successfully!")
        else:
            print(f"User \"{user.username}\" set password error - no such user!")
            logging.error(f"User \"{user.username}\" set password error - no such user!")
            quit(1)
    except Exception as err:
        logging.error(f"User \"{user.username}\" set password error: {err}")
        print(f"User \"{user.username}\" set password error: {err}")

def delete_user(username):
    try:
        user = User.query.filter_by(username=username).first()
        if user:
            db.session.delete(user)
            db.session.commit()
            load_config()
            print(f"User \"{user.username}\" deleted successfully!")
            logging.info(f"User \"{user.username}\" deleted successfully!")
        else:
            print(f"User \"{user.username}\" delete error - no such user!")
            logging.error(f"User \"{user.username}\" delete error - no such user!")
            quit(1)
    except Exception as err:
        logging.error(f"User \"{user.username}\" delete error: {err}")
        print(f"User \"{user.username}\" delete error: {err}")

def add_cache(name,path):
    try:
        new_cache = CachePath(cacheName=name, cachePath=path)
        db.session.add(new_cache)
        db.session.commit()
        updated = CachePath.query.filter_by(cacheName=name).first()
        print(f"Cache path \"{updated.cacheName}\" - \"{updated.cachePath}\" added successfully.")
        logging.info(f"Cache path \"{updated.cacheName}\" - \"{updated.cachePath}\" added successfully.")
    except Exception as err:
        logging.error(f"Add cache error: {err}")
        print(f"Add cache error: {err}")

def del_cache(name):
    try:
        del_cache = CachePath.query.filter_by(cacheName=name).first()
        if del_cache:
            name = del_cache.cacheName
            path = del_cache.cachePath
            db.session.delete(del_cache)
            db.session.commit()
            print(f"Cache \"{name}\" - \"{path}\" deleted successfully.")
            logging.info(f"Cache \"{name}\" - \"{path}\" deleted successfully.")
    except Exception as err:
        logging.error(f"Del cache error: {err}")
        print(f"Del cache error: {err}")

def import_cache(file):
    data = []
    try:
        with open(file, 'r',encoding='utf8') as file2:
            for line in file2:
                stripped = line.strip()
                if not stripped:
                    continue
                parts = stripped.split(maxsplit=1)
                if len(parts) == 2:
                    name, path = parts
                    data.append({"name": name, "path": path})
                else:
                    print(f"Incorrect line skipped: {line}")
                new_entry = CachePath(cacheName=name, cachePath=path)
                db.session.add(new_entry)
        db.session.commit()
        load_config()
        print(f"Bulk cache settings loaded from file successfully.")
        logging.info(f"Bulk cache settings loaded successfully from {file}.")
    except Exception as err:
        logging.error(f"Bulk cache loading error: {err}")
        print(f"Bulk cache loading error: {err}")

async def send_to_telegram(subject,message):
    if TELEGRAM_CHATID and TELEGRAM_TOKEN:
        headers = {
            'Content-Type': 'application/json',
        }
        data = {
            "chat_id": f"{TELEGRAM_CHATID}",
            "text": f"{subject}\n{message}",
        }
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(
                    f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                    headers=headers,
                    json=data
                )
            print(response.status_code)
            if response.status_code != 200:
                logging.error("error", f"Telegram bot error! Status: {response.status_code} Body: {response.text}")
        except Exception as err:
            logging.error(f"Error while sending message to Telegram: {err}")

def load_config():
    #main initialization phase starts here
    global TELEGRAM_TOKEN, TELEGRAM_CHATID, LOG_FILE, CACHE_FOLDER_BEGIN_WITH
    try:
        config = db.session.get(Settings, 1)
        TELEGRAM_TOKEN = config.telegramToken
        TELEGRAM_CHATID = config.telegramChat
        LOG_FILE = config.logFile
        application.secret_key = config.cryptKey
        CACHE_FOLDER_BEGIN_WITH = config.cacheFolderBeginWith
        try:
            logging.basicConfig(filename=LOG_FILE,level=logging.INFO,format='%(asctime)s - Nginx-cache-clean - %(levelname)s - %(message)s',datefmt='%d-%m-%Y %H:%M:%S')
        except Exception as msg:
            logging.error(msg)
            print(f"Load-config error: {msg}")
            quit(1)
    except Exception as msg:
        print(f"Load-config error: {msg}")
        quit(1)
        
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User,int(user_id))

#catch logout form. Deleting cookies and redirect to /
@application.route("/logout", methods=['POST'])
@login_required
def logout():
    logout_user()
    flash("You are logged out", "alert alert-info")
    return redirect(url_for("login"),301)

@application.route("/purge", methods=['POST'])
@login_required
def purge():
    if request.method == 'POST':
        if request.form['purge']:
            record = CachePath.query.filter_by(cacheName=request.form['purge']).first()
            if record:
                path = record.cachePath
                name = record.cacheName
            try:
                #check if name and zone path from POST equals to their real data from DB, and PATH starts with CACHE_FOLDER_BEGIN_WITH value, to prevent of deleting inside root or any other wrong folder.
                if (request.form['purge'] == name) and ((request.form['zone'] == path)) and (path.startswith(CACHE_FOLDER_BEGIN_WITH)):
                    if not os.path.isdir(path):
                        logging.error(f"Purge error: user {current_user.realname}, zone: {name} - {path} - is not a directory!")
                        flash(f"Purge error: Zone: {name} - {path} is not a directory!", "alert alert-danger")
                        return redirect(url_for("index"),301)
                    directory_path = os.path.abspath(path)
                    if directory_path in ('/', '/home', '/root', '/etc', '/var', '/tmp', os.path.expanduser("~")):
                        logging.error(f"Purge error: user {current_user.realname}, zone: {name} - {path} - too dangerous directory is selected!")
                        flash(f"Purge error: Zone: {name} - {path} too dangerous directory is selected!", "alert alert-danger")
                        return redirect(url_for("index"),301)
                    for filename in os.listdir(path):
                        file_path = os.path.join(path, filename)
                        try:
                            if os.path.isfile(file_path) or os.path.islink(file_path):
                                os.unlink(file_path)
                            elif os.path.isdir(file_path):
                                shutil.rmtree(file_path)
                        except Exception as msg:
                            logging.error(f"Purge error: user {current_user.realname}, zone: {name} - {path} - can't delete {file_path}: {msg}!")
                            flash(f"Purge error: Zone: {name} - {path} - some files or folders were not deleted!", "alert alert-warning")
                            return redirect(url_for("index"),301)
                    asyncio.run(send_to_telegram("🍀Nginx-Cache-Clean:",f"Nginx local cache for {name} purged successfully by {current_user.realname}!"))
                    logging.info(f"Nginx cache for {name} - {path} purged successfully by {current_user.realname}!")
                    flash(f"{name} purged successfully!", "alert alert-success")
                    return redirect("/",301)
                else:
                    logging.error(f"Error: Some errors during purging - {name} - {path} - Purge or Zone variable is not set or Path is outside CACHE_FOLDER_BEGIN_WITH security parameter!")
                    asyncio.run(send_to_telegram("💢Nginx-Cache-Clean:",f"Error: Some errors during purging - {name} - {path} - Purge or Zone variable is not set or Path is outside CACHE_FOLDER_BEGIN_WITH security parameter!"))
                    flash(f"Error: Some errors during purging - {name} - {path} - Purge or Zone variable is not set or Path is outside CACHE_FOLDER_BEGIN_WITH security parameter!", "alert alert-danger")
                    return redirect("/",301)
            except Exception as msg:
                logging.error(f"Error: Some errors during purging - {name} - {path} - {msg}!")
                asyncio.run(send_to_telegram("💢Nginx-Cache-Clean:",f"Error: Some errors during- {name} - {path} - {msg}"))
                flash(f"Purge error: Zone: {name} - {path} - some error while purge. See logs.", "alert alert-warning")
                return redirect("/",301)
        else:
            asyncio.run(send_to_telegram("💢Nginx-Cache-Clean:",f"Error: {name} - {path} - variables are not received properly for {current_user.realname}!"))
            logging.error(f"Error: {name} - {path} - variables are not received properly for {current_user.realname}!")
            flash(f"Error: {name} - {path} - variables are not received properly for {current_user.realname}!")
            return redirect("/",301)
    else:
        return redirect("/",301)

#catch login form. Check if user exists in the list and password is correct. If yes - set cookies and redirect to /
@application.route("/login", methods=['GET','POST'])
def login():
    #is this is POST request so we are trying to login
    if request.method == 'POST':
        if current_user.is_authenticated:
            return redirect('/',301)
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            logging.info(f"Login: User {username} logged in")
            return redirect("/",301)
        else:
            logging.error(f"Login: Wrong password \"{password}\" for user \"{username}\"")
            asyncio.run(send_to_telegram("🚷Nginx-Cache-Clean:",f"Login error.Wrong password for user \"{username}\""))
            flash('Wrong username or password!', 'alert alert-danger')
            return render_template("template-login.html")    
    if current_user.is_authenticated:
        return redirect('/',301)
    else:
        return render_template("template-login.html")

@application.route("/", methods=['GET'])
@login_required
def index():
    table = ""
    dir = []
    cache_settings = CachePath.query.all()
    for i, s in enumerate(cache_settings, 1):
        #check is something inside the directory or it's empty
        try:
            dir = os.listdir(s.cachePath)
        except Exception as msg:
            pass
        #if directory is not empty
        if (os.path.exists(s.cachePath) and len(dir) > 0 and dir != "---"):
            table += f"""\n<tr>\n<th scope="row" class="table-success" style="width: 34px;">{i}</th>
            <td class="table-success" ><form method="post" action="/purge"><button type="submit" value="{s.cacheName}" name="purge" class="btn btn-primary">Purge Cache</button>
            <input type="hidden" name="zone" value="{s.cachePath}">
            <td class="table-success" style="width: auto;">{s.cacheName}</td>
            <td class="table-success" style="width: auto;">{s.cachePath}</td>
            <td class="table-success" style="width: auto;">Cache directory is OK</td></form>"""
        #if directory is empty
        elif (os.path.exists(s.cachePath) and len(dir) == 0):
            table += f"""\n<tr>\n<th scope="row" class="table-info" style="width: 34px;">{i}</th>
            <td class="table-info" ><form method="post" action="/purge"><button type="submit" value="{s.cacheName}" name="purge" class="btn btn-primary">Purge?</button>
            <input type="hidden" name="zone" value="{s.cachePath}">
            <td class="table-info" style="width: auto;">{s.cacheName}</td>
            <td class="table-info" style="width: auto;">{s.cachePath}</td>
            <td class="table-info" style="width: auto;">Cache directory is empty</td></form>"""
        #if directory is not exists at all
        else:
            table += f"""\n<tr>\n<th scope="row" class="table-danger" style="width: 34px;">{i}</th>
            <td class="table-danger" >
            <td class="table-danger" style="width: auto;">{s.cacheName}</td>
            <td class="table-danger" style="width: auto;">{s.cachePath}</td>
            <td class="table-danger" style="width: auto;">Cache directory is not exists!</td>"""
    return render_template("template-main.html",table=table)

if __name__ == "__main__":
    application.app_context().push()
    generate_default_config()
    load_config()
    if len(sys.argv) > 1:
        if sys.argv[1] == "--help" or sys.argv[1] == "-h" or sys.argv[1] == "help":
            print(f"""Usage: \n{sys.argv[0]} set chat <chatID>
\tAdd Telegram ChatID for notifications.
{sys.argv[0]} set token <Token>
\tAdd Telegram Token for notifications.
{sys.argv[0]} set logpath <new log file path>
\tAdd Telegram Token for notifications.
{sys.argv[0]} user add <login> <password> <realname>
\tAdd new user with its password and default permissions for all cache pathes.
{sys.argv[0]} user setpwd <user> <new password>
\tSet new password for existing user.
{sys.argv[0]} user del <user>
\tDelete existing user by its login
{sys.argv[0]} cache add <name> <path>
\tAdd new cache path
{sys.argv[0]} cache import <path to file>
\tImport cache records from file
{sys.argv[0]} cache del <name>
\tDelete cache entry
""")
            quit()
        elif sys.argv[1] == "set" and sys.argv[2] == "chat":
            set_telegramChat(sys.argv[3].strip())
        elif sys.argv[1] == "set" and sys.argv[2] == "token":
            set_telegramToken(sys.argv[3].strip())
        elif sys.argv[1] == "set" and sys.argv[2] == "log":
            set_logpath(sys.argv[3].strip())
        elif sys.argv[1] == "user" and sys.argv[2] == "add":
            if (len(sys.argv) == 6):
                register_user(sys.argv[3].strip(),sys.argv[4].strip(),sys.argv[5].strip())
            else:
                print("Error! Enter both username and password")
        elif sys.argv[1] == "user" and sys.argv[2] == "setpwd":
            if (len(sys.argv) == 5):
                update_user(sys.argv[3].strip(),sys.argv[4].strip())
            else:
                print("Error! Enter both username and new password")
        elif sys.argv[1] == "user" and sys.argv[2] == "del":
            if (len(sys.argv) == 4):
                delete_user(sys.argv[3].strip())
            else:
                print("Error! Enter both username and new password")
        elif sys.argv[1] == "cache" and sys.argv[2] == "add":
            if (len(sys.argv) == 5):
                add_cache(sys.argv[3].strip(),sys.argv[4].strip())
            else:
                print("Error! Enter both Name and cache path")
        elif sys.argv[1] == "cache" and sys.argv[2] == "import":
            if (len(sys.argv) == 4):
                import_cache(sys.argv[3].strip())
            else:
                print("Error! Enter path to file with cache list")
        elif sys.argv[1] == "cache" and sys.argv[2] == "del":
            if (len(sys.argv) == 4):
                del_cache(sys.argv[3].strip())
            else:
                print("Error! Enter name of cache entry to delete")
        quit(0)
    application.run(debug=True, host="172.31.255.2", port="80")
