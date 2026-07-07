import os
import shutil
import logging
from flask import current_app
from db.database import CachePath

def build_cache_table() -> str:
  """Builds the HTML table rows shown on the main page, one row per configured cache path."""
  table = ""
  cache_settings = CachePath.query.order_by(CachePath.cacheName).all()
  for i, s in enumerate(cache_settings, 1):
    dir_listing = []
    try:
      dir_listing = os.listdir(s.cachePath)
    except Exception:
      pass
    if os.path.exists(s.cachePath) and len(dir_listing) > 0:
      table += f"""
<tr>
<th scope="row" class="table-success" style="width: 34px;">{i}</th>
<td class="table-success"><form method="post" action="/purge/"><button type="submit" value="{s.cacheName}" name="purge" class="btn btn-primary" onclick="showLoading()">Purge Cache</button>
<input type="hidden" name="zone" value="{s.cachePath}">
<td class="table-success" style="width: auto;">{s.cacheName}</td>
<td class="table-success" style="width: auto;">{s.cachePath}</td>
<td class="table-success" style="width: auto;">Cache directory is OK</td></form>"""
    elif os.path.exists(s.cachePath) and len(dir_listing) == 0:
      table += f"""
<tr>
<th scope="row" class="table-info" style="width: 34px;">{i}</th>
<td class="table-info"><form method="post" action="/purge/"><button type="submit" value="{s.cacheName}" name="purge" class="btn btn-primary" onclick="showLoading()">Purge?</button>
<input type="hidden" name="zone" value="{s.cachePath}">
<td class="table-info" style="width: auto;">{s.cacheName}</td>
<td class="table-info" style="width: auto;">{s.cachePath}</td>
<td class="table-info" style="width: auto;">Cache directory is empty</td></form>"""
    else:
      table += f"""
<tr>
<th scope="row" class="table-danger" style="width: 34px;">{i}</th>
<td class="table-danger">
<td class="table-danger" style="width: auto;">{s.cacheName}</td>
<td class="table-danger" style="width: auto;">{s.cachePath}</td>
<td class="table-danger" style="width: auto;">Cache directory does not exist!</td>"""
  return table

def purge_cache_path(name: str, path: str) -> tuple[bool, str]:
  """Validates the requested cache path against the database and CACHE_FOLDER_BEGIN_WITH security
  boundary, then purges its contents. Returns (success, message)."""
  record = CachePath.query.filter_by(cacheName=name).first()
  if not record or record.cachePath != path:
    return False, f"Zone: {name} - {path} - Purge or Zone variable does not match the database record!"
  cache_folder_begin_with = current_app.config.get("CACHE_FOLDER_BEGIN_WITH", "")
  if not path.startswith(cache_folder_begin_with):
    return False, f"Zone: {name} - {path} - is outside of the allowed CACHE_FOLDER_BEGIN_WITH security parameter!"
  if not os.path.isdir(path):
    return False, f"Zone: {name} - {path} - is not a directory!"
  directory_path = os.path.abspath(path)
  if directory_path in ('/', '/home', '/root', '/etc', '/var', '/tmp', os.path.expanduser("~")):
    return False, f"Zone: {name} - {path} - too dangerous directory is selected!"
  for filename in os.listdir(path):
    file_path = os.path.join(path, filename)
    try:
      if os.path.isfile(file_path) or os.path.islink(file_path):
        os.unlink(file_path)
      elif os.path.isdir(file_path):
        shutil.rmtree(file_path)
    except Exception as msg:
      logging.error(f"purge_cache_path(): can't delete {file_path}: {msg}")
      return False, f"Zone: {name} - {path} - some files or folders were not deleted!"
  return True, f"{name} purged successfully!"
