import logging
from db.db import db
from db.database import User
from werkzeug.security import generate_password_hash

def register_user(username: str, realname: str, password: str) -> None:
  """CLI only function: adds new user and saves to database"""
  logging.info("-----------------------Starting CLI functions: register_user")
  try:
    if User.query.filter_by(username=username).first():
      print(f"User \"{username}\" creation error - already exists!")
      logging.error(f"cli>User \"{username}\" creation error - already exists!")
      quit(1)
    new_user = User(
      username=username,
      password_hash=generate_password_hash(password),
      realname=realname,
      rights=1
    )
    db.session.add(new_user)
    db.session.commit()
    print(f"New user \"{username}\" - \"{realname}\" created successfully!")
    logging.info(f"cli>New user \"{username}\" - \"{realname}\" created successfully!")
  except Exception as err:
    logging.error(f"cli>User \"{username}\" - \"{realname}\" creation error: {err}")
    print(f"User \"{username}\" - \"{realname}\" creation error: {err}")
    quit(1)

def update_user(username: str, password: str) -> None:
  """CLI only function: password change for an existing user"""
  logging.info("-----------------------Starting CLI functions: update_user")
  try:
    user = User.query.filter_by(username=username).first()
    if not user:
      print(f"User \"{username}\" set password error - no such user!")
      logging.error(f"cli>User \"{username}\" set password error - no such user!")
      quit(1)
    user.password_hash = generate_password_hash(password)
    db.session.commit()
    print(f"Password for user \"{user.username}\" updated successfully!")
    logging.info(f"cli>Password for user \"{user.username}\" updated successfully!")
  except Exception as err:
    logging.error(f"cli>User \"{username}\" set password error: {err}")
    print(f"User \"{username}\" set password error: {err}")
    quit(1)

def delete_user(username: str) -> None:
  """CLI only function: deletes an existing user from database"""
  logging.info("-----------------------Starting CLI functions: delete_user")
  try:
    user = User.query.filter_by(username=username).first()
    if not user:
      print(f"User \"{username}\" delete error - no such user!")
      logging.error(f"cli>User \"{username}\" delete error - no such user!")
      quit(1)
    db.session.delete(user)
    db.session.commit()
    print(f"User \"{username}\" deleted successfully!")
    logging.info(f"cli>User \"{username}\" deleted successfully!")
  except Exception as err:
    logging.error(f"cli>User \"{username}\" delete error: {err}")
    print(f"User \"{username}\" delete error: {err}")
    quit(1)

def show_users() -> None:
  """CLI only function: shows all users in database"""
  logging.info("-----------------------Starting CLI functions: show_users")
  users = User.query.order_by(User.username).all()
  if len(users) == 0:
    print("No users found in DB!")
    return
  for s in users:
    print(f"ID: {s.id}, Login: {s.username}, RealName: {s.realname}, Rights: {s.rights}, Created: {s.created}")

def make_admin_user(username: str) -> None:
  """CLI only function: grants the given user admin rights"""
  logging.info("-----------------------Starting CLI functions: make_admin_user")
  user = User.query.filter_by(username=username).first()
  if not user:
    print(f"User \"{username}\" set admin rights error - no such user!")
    logging.error(f"cli>User \"{username}\" set admin rights error - no such user!")
    quit(1)
  user.rights = 255
  db.session.commit()
  print(f"User \"{username}\" successfully set as admin!")
  logging.info(f"cli>User \"{username}\" successfully set as admin!")

def remove_admin_user(username: str) -> None:
  """CLI only function: removes admin rights from the given user"""
  logging.info("-----------------------Starting CLI functions: remove_admin_user")
  user = User.query.filter_by(username=username).first()
  if not user:
    print(f"User \"{username}\" unset admin rights error - no such user!")
    logging.error(f"cli>User \"{username}\" unset admin rights error - no such user!")
    quit(1)
  user.rights = 1
  db.session.commit()
  print(f"User \"{username}\" successfully set as the regular user!")
  logging.info(f"cli>User \"{username}\" successfully set as the regular user!")
