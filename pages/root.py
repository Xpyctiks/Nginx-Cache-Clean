import logging
from flask import Blueprint, render_template, redirect, request, flash
from flask_login import login_required, current_user
from functions.cache_func import build_cache_table, purge_cache_path
from functions.send_to_telegram import send_to_telegram

root_bp = Blueprint("root", __name__)

@root_bp.route("/", methods=['GET'])
@login_required
def index():
  """Main page: shows the status of every configured cache path with a purge button."""
  table = build_cache_table()
  return render_template("template-main.html", table=table)

@root_bp.route("/purge/", methods=['POST'])
@login_required
def purge():
  """POST request processor: purges the selected cache path after validating it against the DB."""
  name = request.form.get('purge', '').strip()
  path = request.form.get('zone', '').strip()
  if not name or not path:
    logging.error(f"purge(): variables not received properly for {current_user.realname}!")
    send_to_telegram(f"Error: variables are not received properly for {current_user.realname}!", "💢Nginx-Cache-Clean:")
    flash("Error: variables are not received properly!", "alert alert-danger")
    return redirect("/", 302)
  success, message = purge_cache_path(name, path)
  if success:
    logging.info(f"Nginx cache for {name} - {path} purged successfully by {current_user.realname}!")
    send_to_telegram(f"Nginx local cache for {name} purged successfully by {current_user.realname}!", "🍀Nginx-Cache-Clean:")
    flash(message, "alert alert-success")
  else:
    logging.error(f"Purge error: user {current_user.realname}, {message}")
    send_to_telegram(f"Purge error by {current_user.realname}: {message}", "💢Nginx-Cache-Clean:")
    flash(f"Purge error: {message}", "alert alert-danger")
  return redirect("/", 302)
