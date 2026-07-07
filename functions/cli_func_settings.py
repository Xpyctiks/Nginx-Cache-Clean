import logging
from flask import current_app
from db.db import db
from db.database import Settings
from functions.load_config import load_config

def set_telegramChat(tgChat: str) -> None:
  """CLI only function: sets Telegram ChatID value in database"""
  logging.info("-----------------------Starting CLI functions: set_telegramChat")
  t = Settings(id=1, telegramChat=tgChat.strip())
  db.session.merge(t)
  db.session.commit()
  load_config(current_app)
  print("Telegram ChatID added successfully")
  logging.info("cli>Telegram ChatID updated successfully!")

def set_telegramToken(tgToken: str) -> None:
  """CLI only function: sets Telegram Token value in database"""
  logging.info("-----------------------Starting CLI functions: set_telegramToken")
  t = Settings(id=1, telegramToken=tgToken.strip())
  db.session.merge(t)
  db.session.commit()
  load_config(current_app)
  print("Telegram Token added successfully")
  logging.info("cli>Telegram Token updated successfully!")

def set_logpath(logpath: str) -> None:
  """CLI only function: sets logger file path value in database"""
  logging.info("-----------------------Starting CLI functions: set_logpath")
  t = Settings(id=1, logFile=logpath.strip())
  db.session.merge(t)
  db.session.commit()
  load_config(current_app)
  updated = db.session.get(Settings, 1)
  print(f"logPath updated successfully. New log path: \"{updated.logFile}\"")
  logging.info(f"cli>logPath updated to \"{updated.logFile}\"")

def set_cacheFolderBeginWith(path: str) -> None:
  """CLI only function: sets the CACHE_FOLDER_BEGIN_WITH security boundary in database"""
  logging.info("-----------------------Starting CLI functions: set_cacheFolderBeginWith")
  t = Settings(id=1, cacheFolderBeginWith=path.strip())
  db.session.merge(t)
  db.session.commit()
  load_config(current_app)
  updated = db.session.get(Settings, 1)
  print(f"cacheFolderBeginWith updated successfully to: \"{updated.cacheFolderBeginWith}\"")
  logging.info(f"cli>cacheFolderBeginWith updated to \"{updated.cacheFolderBeginWith}\"")

def set_autheliaLogoutUrl(url: str) -> None:
  """CLI only function: sets the Authelia logout redirect URL in database"""
  logging.info("-----------------------Starting CLI functions: set_autheliaLogoutUrl")
  t = Settings(id=1, autheliaLogoutUrl=url.strip())
  db.session.merge(t)
  db.session.commit()
  load_config(current_app)
  updated = db.session.get(Settings, 1)
  print(f"Authelia logout URL updated successfully to: \"{updated.autheliaLogoutUrl}\"")
  logging.info(f"cli>Authelia logout URL updated to \"{updated.autheliaLogoutUrl}\"")

def show_config() -> None:
  """CLI only function: shows all current config values loaded from database"""
  print(f"""
Telegram ChatID:          {current_app.config["TELEGRAM_CHATID"]}
Telegram Token:           {current_app.config["TELEGRAM_TOKEN"]}
Log file:                 {current_app.config["LOG_FILE"]}
Cache folder begins with: {current_app.config["CACHE_FOLDER_BEGIN_WITH"]}
Authelia logout URL:      {current_app.config["AUTHELIA_LOGOUT_URL"]}
Secret key:               {current_app.secret_key}
""")
