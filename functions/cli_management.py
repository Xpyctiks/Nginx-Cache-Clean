import functools
import click
from functions.cli_func_user import *
from functions.cli_func_settings import *
from functions.cli_func_cache import *

def with_app_context(func):
  """Decorator to run a CLI command inside the Flask app context.
  Must preserve func.__name__/__doc__ via functools.wraps - click.command() derives the
  command name from the wrapped function's __name__, and without wraps() every decorated
  command would be named "wrapper", silently colliding with one another in the same group."""
  @functools.wraps(func)
  def wrapper(*args, **kwargs):
    from main import application
    with application.app_context():
      return func(*args, **kwargs)
  return wrapper

@click.group(context_settings=dict(help_option_names=["-h", "--help"]))
def show_cli():
  """Nginx-Cache-Clean CLI"""
  pass

# SET
@show_cli.group()
def set():
  """Set configuration values"""
  pass

@set.command()
@click.argument("chatid")
@with_app_context
def chat(chatid):
  """Set Telegram Chat ID"""
  set_telegramChat(chatid)

@set.command()
@click.argument("token")
@with_app_context
def token(token):
  """Set Telegram bot token"""
  set_telegramToken(token)

@set.command()
@click.argument("path")
@with_app_context
def log(path):
  """Set log file path"""
  set_logpath(path)

@set.command()
@click.argument("path")
@with_app_context
def cachefolder(path):
  """Set the allowed cache folder root (security boundary)"""
  set_cacheFolderBeginWith(path)

@set.command("logouturl")
@click.argument("url")
@with_app_context
def set_logout_url(url):
  """Set the Authelia logout redirect URL"""
  set_autheliaLogoutUrl(url)

# USER
@show_cli.group()
def user():
  """User management"""
  pass

@user.command("add")
@click.argument("username")
@click.argument("realname")
@click.argument("password")
@with_app_context
def user_add(username, realname, password):
  """Add new user"""
  register_user(username, realname, password)

@user.command("del")
@click.argument("username")
@with_app_context
def user_del(username):
  """Delete user"""
  delete_user(username)

@user.command("setpwd")
@click.argument("username")
@click.argument("password")
@with_app_context
def user_setpwd(username, password):
  """Change user password"""
  update_user(username, password)

@user.command("setadmin")
@click.argument("username")
@with_app_context
def user_setadmin(username):
  """Grant admin rights"""
  make_admin_user(username)

@user.command("unsetadmin")
@click.argument("username")
@with_app_context
def user_unsetadmin(username):
  """Remove admin rights"""
  remove_admin_user(username)

# CACHE
@show_cli.group()
def cache():
  """Cache paths management"""
  pass

@cache.command("add")
@click.argument("name")
@click.argument("path")
@with_app_context
def cache_add(name, path):
  """Add new cache path"""
  add_cache(name, path)

@cache.command("del")
@click.argument("name")
@with_app_context
def cache_del(name):
  """Delete cache path"""
  del_cache(name)

@cache.command("import")
@click.argument("file")
@with_app_context
def cache_import(file):
  """Bulk import cache paths from file"""
  import_cache(file)

# SHOW
@show_cli.group()
def show():
  """Show information"""
  pass

@show.command("users")
@with_app_context
def show_users_cmd():
  show_users()

@show.command("config")
@with_app_context
def show_config_cmd():
  show_config()

@show.command("cache")
@with_app_context
def show_cache_cmd():
  show_cache()

# VERSION
@show_cli.command("version")
def show_version():
  """Show application version"""
  from main import VERSION
  click.echo(VERSION)
