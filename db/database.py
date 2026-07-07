from .db import db
from werkzeug.security import check_password_hash
from flask_login import UserMixin
from datetime import datetime

class User(UserMixin, db.Model):
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(80), unique=True, nullable=False)
  realname = db.Column(db.String(80), nullable=False)
  password_hash = db.Column(db.String(250), nullable=False)
  rights = db.Column(db.Integer, nullable=False, default=1)
  created = db.Column(db.DateTime, default=datetime.now)
  def check_password(self, password):
    return check_password_hash(self.password_hash, password)

class Settings(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  telegramChat = db.Column(db.String(16), nullable=True)
  telegramToken = db.Column(db.String(64), nullable=True)
  logFile = db.Column(db.String(512), nullable=True)
  cryptKey = db.Column(db.String(64), nullable=True)
  cacheFolderBeginWith = db.Column(db.String(64), nullable=True)
  autheliaLogoutUrl = db.Column(db.String(512), nullable=True, default="")

class CachePath(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  cacheName = db.Column(db.String(32), nullable=False, unique=True)
  cachePath = db.Column(db.String(512), nullable=False, unique=True)
  created = db.Column(db.DateTime, default=datetime.now)
