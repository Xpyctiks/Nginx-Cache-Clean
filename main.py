#!/usr/local/bin/python3

import os
from flask import Flask
from flask_login import LoginManager
from datetime import timedelta

VERSION = "2.0.0"
CONFIG_DIR = "/etc/nginx-cache-clean/"
DB_FILE = os.path.join(CONFIG_DIR, "nginx-cache-clean.db")
application = Flask(__name__)
application.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + DB_FILE
application.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
application.config['SESSION_COOKIE_SECURE'] = False
application.config['SESSION_COOKIE_HTTPONLY'] = True
application.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
application.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

from db.db import db
from db.database import User
db.init_app(application)

from functions.load_config import load_config, generate_default_config, migrate_schema
generate_default_config(application, CONFIG_DIR, DB_FILE)
with application.app_context():
  migrate_schema(application)
  db.create_all()
load_config(application)
application.secret_key = application.config["SECRET_KEY"]

login_manager = LoginManager()
login_manager.login_view = "main.login.show_login_page"
login_manager.session_protection = "strong"
login_manager.init_app(application)

from functions.authelia_auth import try_authelia_login
application.before_request(try_authelia_login)

@login_manager.user_loader
def load_user(user_id):
  return db.session.get(User, int(user_id))

from pages import blueprint as routes_blueprint
application.register_blueprint(routes_blueprint)

from functions.cli_management import show_cli

if __name__ == "__main__":
  show_cli()
