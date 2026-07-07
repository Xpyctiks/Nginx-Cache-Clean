import logging
from flask import redirect, flash, Blueprint, session, current_app
from flask_login import logout_user, login_required, current_user

logout_bp = Blueprint("logout", __name__)

@logout_bp.route("/logout/", methods=['POST'])
@login_required
def do_logout():
  """POST request processor: logs the user out. Redirects to the Authelia logout URL when
  one is configured, otherwise back to the local /login/ page."""
  logging.info(f"User {current_user.realname} is logging out...")
  logout_user()
  session.clear()
  authelia_logout_url = current_app.config.get("AUTHELIA_LOGOUT_URL", "")
  if authelia_logout_url:
    return redirect(authelia_logout_url, 302)
  flash("You are logged out", "alert alert-info")
  return redirect("/login/", 302)
