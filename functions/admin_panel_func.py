import logging
from flask import flash
from flask_login import current_user
from werkzeug.security import generate_password_hash
from db.db import db
from db.database import Settings, User
from functions.rights_required import rights_required

@rights_required(255)
def handler_settings(form):
  """Handler for saving global settings to DB, received from the admin panel."""
  logging.info(f"---------------------------Processing global settings from admin panel by {current_user.realname}---------------------------")
  try:
    for db_field in form:
      if db_field == "buttonSaveSettings":
        continue
      data = {"id": 1, db_field: form.get(db_field)}
      t = Settings(**data)
      db.session.merge(t)
    db.session.commit()
    logging.info(f"Admin {current_user.realname}>Saving global settings done---------------------------")
    flash('New settings saved and applied!', 'alert alert-success')
  except Exception as err:
    logging.error(f"Admin {current_user.realname}>handler_settings() global error: {err}")
    flash('Error saving application settings!', 'alert alert-danger')

@rights_required(255)
def handler_users(form):
  """Handler for adding/editing/deleting users and toggling admin rights, received from the admin panel."""
  logging.info(f"---------------------------Processing user management from admin panel by {current_user.realname}---------------------------")
  try:
    if "buttonDeleteUser" in form:
      user = User.query.filter_by(id=int(form.get('buttonDeleteUser').strip())).first()
      if not user:
        logging.error(f"Admin {current_user.realname}>User with ID {form.get('buttonDeleteUser').strip()} deletion error - no such user!")
        flash(f'Deletion error - user with ID {form.get("buttonDeleteUser").strip()} does not exist!', 'alert alert-warning')
        return
      if user.id == current_user.id:
        flash('You cannot delete your own account!', 'alert alert-danger')
        return
      username = user.username
      db.session.delete(user)
      db.session.commit()
      logging.info(f"Admin {current_user.realname}>User {username} deleted successfully!")
      flash(f'User "{username}" deleted successfully!', 'alert alert-success')
      return
    if "buttonAddUser" in form:
      username = form.get("new-username", "").strip()
      realname = form.get("new-realname", "").strip()
      password = form.get("new-password", "").strip()
      if not username or not realname or not password:
        logging.error(f"Admin {current_user.realname}>Some of the required fields for the new user were not received!")
        flash('Some of the required fields for the new user were not received by the server!', 'alert alert-warning')
        return
      if User.query.filter_by(username=username).first():
        logging.error(f"Admin {current_user.realname}>User \"{username}\" creation error - already exists!")
        flash(f'User "{username}" already exists!', 'alert alert-danger')
        return
      rights = 255 if "new-is-admin" in form else 1
      new_user = User(username=username, realname=realname, password_hash=generate_password_hash(password), rights=rights)
      db.session.add(new_user)
      db.session.commit()
      logging.info(f"Admin {current_user.realname}>User {username} created successfully (rights={rights})!")
      flash(f'User "{username}" created successfully!', 'alert alert-success')
      return
    if "buttonMakeAdminUser" in form:
      user = User.query.filter_by(id=int(form.get('buttonMakeAdminUser').strip())).first()
      if not user:
        logging.error(f"Admin {current_user.realname}>User with ID {form.get('buttonMakeAdminUser').strip()} set admin rights error - no such user!")
        flash(f'Error - user with ID {form.get("buttonMakeAdminUser").strip()} does not exist!', 'alert alert-warning')
        return
      user.rights = 255
      db.session.commit()
      logging.info(f"Admin {current_user.realname}>User {user.username} successfully set as admin!")
      flash(f'User "{user.username}" is now an administrator!', 'alert alert-success')
      return
    if "buttonRemoveAdminUser" in form:
      user = User.query.filter_by(id=int(form.get('buttonRemoveAdminUser').strip())).first()
      if not user:
        logging.error(f"Admin {current_user.realname}>User with ID {form.get('buttonRemoveAdminUser').strip()} unset admin rights error - no such user!")
        flash(f'Error - user with ID {form.get("buttonRemoveAdminUser").strip()} does not exist!', 'alert alert-warning')
        return
      if user.id == current_user.id:
        flash('You cannot remove your own admin rights!', 'alert alert-danger')
        return
      user.rights = 1
      db.session.commit()
      logging.info(f"Admin {current_user.realname}>User {user.username} successfully set as the regular user!")
      flash(f'User "{user.username}" is now a regular user!', 'alert alert-success')
      return
    if "buttonEditUser" in form:
      user = User.query.filter_by(id=int(form.get('buttonEditUser').strip())).first()
      if not user:
        logging.error(f"Admin {current_user.realname}>User with ID {form.get('buttonEditUser').strip()} edit error - no such user!")
        flash(f'Error - user with ID {form.get("buttonEditUser").strip()} does not exist!', 'alert alert-warning')
        return
      realname = form.get("edit-realname", "").strip()
      password = form.get("edit-password", "").strip()
      if realname:
        user.realname = realname
      if password:
        user.password_hash = generate_password_hash(password)
      db.session.commit()
      logging.info(f"Admin {current_user.realname}>User {user.username} updated successfully!")
      flash(f'User "{user.username}" updated successfully!', 'alert alert-success')
      return
  except Exception as err:
    logging.error(f"Admin {current_user.realname}>handler_users() global error: {err}")
    flash('Error processing user management action!', 'alert alert-danger')
