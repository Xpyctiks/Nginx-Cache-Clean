import os
import logging
import string
import random
from sqlalchemy import inspect, text
from db.db import db
from db.database import Settings

def load_config(application):
  """Important function - loads all configuration values from Sqlite3 database when an application starts"""
  with application.app_context():
    try:
      config = db.session.get(Settings, 1)
      application.config.update({
        "TELEGRAM_TOKEN": f"{config.telegramToken or ''}",
        "TELEGRAM_CHATID": f"{config.telegramChat or ''}",
        "LOG_FILE": f"{config.logFile or ''}",
        "CACHE_FOLDER_BEGIN_WITH": f"{config.cacheFolderBeginWith or ''}",
        "SECRET_KEY": f"{config.cryptKey or ''}",
        "AUTHELIA_LOGOUT_URL": f"{config.autheliaLogoutUrl or ''}"
      })
      logging.basicConfig(filename=config.logFile,level=logging.INFO,format='%(asctime)s - Nginx-Cache-Clean - %(levelname)s - %(message)s',datefmt='%d-%m-%Y %H:%M:%S')
      logging.getLogger('werkzeug').setLevel(logging.WARNING)
      logging.getLogger("httpx").setLevel(logging.WARNING)
    except Exception as msg:
      print(f"Load-config error: {msg}")
      quit(1)

def generate_default_config(application, CONFIG_DIR: str, DB_FILE: str):
  """Checks on every application start if the config DB exists. If not - creates it with default values."""
  with application.app_context():
    if not os.path.isfile(DB_FILE):
      length = 64
      characters = string.ascii_letters + string.digits
      cookie_salt = ''.join(random.choice(characters) for _ in range(length))
      default_settings = Settings(
        id=1,
        telegramChat="",
        telegramToken="",
        logFile="/var/log/nginx-cache-clean.log",
        cryptKey=cookie_salt,
        cacheFolderBeginWith="/tmp",
        autheliaLogoutUrl=""
      )
      try:
        if not os.path.exists(CONFIG_DIR):
          os.mkdir(CONFIG_DIR)
        db.create_all()
        db.session.add(default_settings)
        db.session.commit()
        print(f"First launch. Default database created in {DB_FILE}. You need to add telegram ChatID and Token if you want to get notifications")
      except Exception as msg:
        print(f"Generate-default-config error: {msg}")
        quit(1)

def migrate_schema(application):
  """Additive-only upgrade helper: adds columns introduced in newer versions (rights, autheliaLogoutUrl)
  to an existing SQLite database, so older installs keep working after an update without a manual migration."""
  with application.app_context():
    try:
      inspector = inspect(db.engine)
      existing_tables = inspector.get_table_names()
      with db.engine.begin() as conn:
        if "user" in existing_tables:
          columns = [c["name"] for c in inspector.get_columns("user")]
          if "rights" not in columns:
            conn.execute(text("ALTER TABLE user ADD COLUMN rights INTEGER NOT NULL DEFAULT 1"))
            print("migrate_schema(): added 'rights' column to 'user' table")
        if "settings" in existing_tables:
          columns = [c["name"] for c in inspector.get_columns("settings")]
          if "autheliaLogoutUrl" not in columns:
            conn.execute(text("ALTER TABLE settings ADD COLUMN autheliaLogoutUrl VARCHAR(512) DEFAULT ''"))
            print("migrate_schema(): added 'autheliaLogoutUrl' column to 'settings' table")
    except Exception as err:
      print(f"migrate_schema() error: {err}")
      quit(1)
