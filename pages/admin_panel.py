import logging
from datetime import datetime
from flask import redirect, Blueprint, request, render_template, flash
from flask_login import login_required, current_user
from db.database import Settings, User
from functions.send_to_telegram import send_to_telegram
from functions.admin_panel_func import handler_settings, handler_users
from functions.rights_required import rights_required

admin_panel_bp = Blueprint("admin_panel", __name__)

@admin_panel_bp.route("/admin_panel/", methods=['GET'])
@login_required
@rights_required(255)
def admin_panel():
  return redirect("/admin_panel/settings/", 302)

@admin_panel_bp.route("/admin_panel/", methods=['POST'])
@login_required
@rights_required(255)
def catch_admin_panel():
  """POST request processor: dispatches every /admin_panel form submission to its handler."""
  try:
    if "buttonSaveSettings" in request.form:
      handler_settings(request.form)
      return redirect("/admin_panel/settings/", 302)
    elif any(k in request.form for k in ("buttonAddUser", "buttonDeleteUser", "buttonMakeAdminUser", "buttonRemoveAdminUser", "buttonEditUser")):
      handler_users(request.form)
      return redirect("/admin_panel/users/", 302)
    else:
      logging.error("Something unrecognized was received by /admin_panel via POST request.")
      send_to_telegram("Something unrecognized was received by /admin_panel via POST request.", "🚒Nginx-Cache-Clean error:")
      flash('Error! No recognized action was submitted to /admin_panel!', 'alert alert-danger')
      return redirect("/admin_panel/settings/", 302)
  except Exception as err:
    logging.error(f"catch_admin_panel(): global error {err}")
    flash('General admin panel error! See logs.', 'alert alert-danger')
    return redirect("/", 302)

@admin_panel_bp.route("/admin_panel/settings/", methods=['GET'])
@login_required
@rights_required(255)
def admin_panel_settings():
  try:
    html_data = """
<div class="card mx-auto" style="max-width: 80vw;" id="SettingsBlock">
  <form action="/admin_panel/" method="POST">"""
    settings = Settings.query.all()
    for setting in settings:
      for column in setting.__table__.columns:
        if column.name == "id":
          continue
        html_data += f"""
<div class="input-group mb-2">
  <span class="input-group-text settings-label">{column.name}:</span>
  <input type="text" class="form-control" name="{column.name}" value="{getattr(setting, column.name) or ''}">
</div>"""
    html_data += """
  <div class="d-grid mt-2 col-12 col-md-4 mx-auto">
    <button type="submit" class="btn btn-success SaveSettings-btn" name="buttonSaveSettings" onclick="showLoading()">Save settings</button>
  </div>
 </form>
</div>"""
    return render_template("template-admin_panel.html", active1="active", data=html_data)
  except Exception as err:
    logging.error(f"admin_panel_settings(): global error {err}")
    flash('General data display error! See logs.', 'alert alert-danger')
    return redirect("/", 302)

@admin_panel_bp.route("/admin_panel/users/", methods=['GET'])
@login_required
@rights_required(255)
def admin_panel_users():
  try:
    html_data = """
<div class="card mx-auto" style="max-width: 90vw;" id="SettingsBlock">
  <table class="table table-bordered">
  <thead>
  <tr class="table-warning">
    <th scope="col" style="width: 45px;">ID:</th>
    <th scope="col" style="width: 150px;">Login:</th>
    <th scope="col" style="width: 200px;">Real name:</th>
    <th scope="col" style="width: 220px;">New password:</th>
    <th scope="col" style="width: 130px;">Admin (255)?:</th>
    <th scope="col" style="width: 190px;">Created:</th>
  </tr>
  </thead>
  <tbody>"""
    users = User.query.order_by(User.username).all()
    for s in users:
      if s.rights >= 255:
        rights_button = f'<button type="submit" class="btn btn-outline-warning AdminUser-btn" name="buttonRemoveAdminUser" onclick="showLoading()" value="{s.id}" title="Remove admin rights from this user.">🚶</button>'
      else:
        rights_button = f'<button type="submit" class="btn btn-outline-warning AdminUser-btn" name="buttonMakeAdminUser" onclick="showLoading()" value="{s.id}" title="Grant admin rights to this user.">👑</button>'
      html_data += f"""
  <tr class="table-success">
    <form action="/admin_panel/" method="POST">
    <td>{s.id}
    <button type="submit" class="btn btn-outline-danger DeleteUser-btn" name="buttonDeleteUser" onclick="showLoading()" value="{s.id}" title="Delete this user.">❌</button>
    </td>
    <td>{s.username}</td>
    <td><input type="text" class="form-control" name="edit-realname" value="{s.realname}"></td>
    <td><input type="password" class="form-control" name="edit-password" placeholder="leave blank to keep current" autocomplete="new-password"></td>
    <td class="text-center">{s.rights}&nbsp;{rights_button}</td>
    <td>{datetime.strftime(s.created,"%d.%m.%Y %H:%M:%S")}
    <button type="submit" class="btn btn-outline-success" name="buttonEditUser" onclick="showLoading()" value="{s.id}" title="Save changes for this user.">💾</button>
    </td>
    </form>
  </tr>"""
    html_data += """
  </tbody>
  </table>
  <form action="/admin_panel/" method="POST">
  <div class="input-group mb-2">
  <span class="input-group-text">Login:</span>
  <input type="text" class="form-control" name="new-username" required>
  <span class="input-group-text">Password:</span>
  <input type="text" class="form-control" name="new-password" required>
  <span class="input-group-text">Real name:</span>
  <input type="text" class="form-control" name="new-realname" required>
  <span class="input-group-text">Admin rights&nbsp;<input class="form-check-input" type="checkbox" name="new-is-admin"></span>
  <button type="submit" class="btn btn-success" name="buttonAddUser" onclick="showLoading()">Create user</button>
   </div>
  </form>
 </div>
</div>"""
    return render_template("template-admin_panel.html", active2="active", data=html_data)
  except Exception as err:
    logging.error(f"admin_panel_users(): global error {err}")
    flash('General data display error! See logs.', 'alert alert-danger')
    return redirect("/", 302)
