import logging
from flask import render_template, request, redirect, flash, Blueprint
from flask_login import login_user, current_user
from datetime import timedelta
from db.database import User
from functions.send_to_telegram import send_to_telegram

login_bp = Blueprint("login", __name__)

@login_bp.route("/login/", methods=['POST'])
def do_login():
  """POST request processor: logs the user in via local username/password."""
  try:
    if current_user.is_authenticated:
      return redirect('/', 302)
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
      login_user(user, remember=True, duration=timedelta(hours=8))
      logging.info(f"Login: User {username} logged in")
      return redirect("/", 302)
    logging.error(f"Login: Wrong password for user \"{username}\"")
    send_to_telegram(f"Login error. Wrong password for user \"{username}\"", "🚷Nginx-Cache-Clean:")
    flash('Wrong username or password!', 'alert alert-danger')
    return redirect("/login/", 302)
  except Exception as err:
    logging.error(f"do_login(): general error: {err}")
    send_to_telegram(f"do_login(): general error: {err}", "🚒Nginx-Cache-Clean error:")
    flash('Unexpected error during login! See logs.', 'alert alert-danger')
    return redirect("/login/", 302)

@login_bp.route("/login/", methods=['GET'])
def show_login_page():
  """GET request: shows the /login page"""
  if current_user.is_authenticated:
    return redirect('/', 302)
  return render_template("template-login.html")

@login_bp.route("/login/authelia/", methods=['GET'])
def login_via_authelia():
  """GET request: entry point protected by reverse-proxy forward-auth (auth_request).
  Nginx must enforce Authelia authentication on this exact location (unlike the pass-through
  mode used for /login/), so an unauthenticated browser is sent to the Authelia portal first
  and only reaches this handler once the Remote-User header is set - at which point
  try_authelia_login() (before_request hook) has already logged the user in."""
  if current_user.is_authenticated:
    return redirect('/', 302)
  logging.warning("login_via_authelia(): reached without a valid Remote-User header")
  flash('Could not sign in via Authelia. Check the reverse-proxy configuration.', 'alert alert-danger')
  return redirect('/login/', 302)
