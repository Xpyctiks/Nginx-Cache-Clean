-Python web application with CLI functions allows to purge Nginx folders with cached files.  
-Uses sqlite3 DB to store options.  
-User management (with admin rights) and cache path management via CLI or the web admin panel.  
-Local username/password login, plus optional hybrid Authelia (reverse-proxy forward-auth) SSO login.  
-Bulk import of cache pathes from file in simple format:  
<name> <path>  
-Security variable CACHE_FOLDER_BEGIN_WITH which used to confirm you are not purging the root folder in any way  
-Sending important alerts or notoification to Telegram if ChatID and Token are set.  

# Project structure
```
main.py                     - application entry point / bootstrap / CLI launcher
db/
  db.py                     - SQLAlchemy instance
  database.py               - User, Settings, CachePath models
functions/
  load_config.py            - reads Settings from DB into app.config, first-launch DB init, schema upgrades
  authelia_auth.py          - hybrid Authelia (Remote-User header) auto-login
  rights_required.py        - @rights_required(255) decorator for admin-only routes
  send_to_telegram.py       - background Telegram notifications
  cache_func.py             - cache table rendering + purge logic
  admin_panel_func.py       - admin panel form handlers (settings, users, rights)
  cli_func_user.py          - CLI: user management
  cli_func_settings.py      - CLI: settings management
  cli_func_cache.py         - CLI: cache path management
  cli_management.py         - click CLI command groups
pages/
  root.py                   - GET / , POST /purge/
  login.py                  - GET/POST /login/ , GET /login/authelia/
  logout.py                 - POST /logout/
  admin_panel.py            - /admin_panel/... (settings + users/rights management)
static/
  css/, js/, images/        - per-page stylesheets, scripts and favicons
templates/
  template-main.html, template-login.html, template-admin_panel.html
```

# Authelia (hybrid SSO) setup
The app supports two login modes at the same time:
- Local login: username/password form on `/login/`.
- Authelia SSO: if your reverse proxy protects `/login/authelia/` with Authelia's `auth_request`
  (so it only lets the request through once Authelia has authenticated the user and set the
  `Remote-User` header), the app auto-logs-in the matching local user (matched by `username`).
  A user with that username must already exist locally - Authelia only vouches for identity,
  it does not create accounts.

Set the Authelia logout URL so that clicking "Logout" also ends the Authelia session:
```
main.py set logouturl "https://auth.example.com/logout"
```
If it's not set, logging out just returns to the local `/login/` page.

# CLI usage
CLI commands run via `main.py` (click-based) and require the Flask app context, so they must
be run from the project directory with the same Python environment as the web app:
```
python3 main.py set chat <chatID>              Set Telegram ChatID for notifications
python3 main.py set token <Token>               Set Telegram bot Token for notifications
python3 main.py set log <path>                  Set log file path
python3 main.py set cachefolder <path>          Set the CACHE_FOLDER_BEGIN_WITH security boundary
python3 main.py set logouturl <url>             Set the Authelia logout redirect URL

python3 main.py user add <login> <realname> <password>   Add new user
python3 main.py user setpwd <login> <password>            Set new password for existing user
python3 main.py user setadmin <login>                     Grant admin (rights=255) access
python3 main.py user unsetadmin <login>                   Remove admin access
python3 main.py user del <login>                          Delete existing user

python3 main.py cache show                      Show all cache path entries
python3 main.py cache add <name> <path>         Add new cache path
python3 main.py cache import <path to file>     Bulk import cache paths from file
python3 main.py cache del <name>                Delete cache path entry

python3 main.py show config                     Show current configuration
python3 main.py show users                      Show all users
python3 main.py show cache                      Show all cache path entries
python3 main.py show version                    Show application version
```
Admin users (rights=255) can also manage settings, users and admin rights from the web
admin panel at `/admin_panel/`.

# UWSGI server config example:  
```
[uwsgi]  
module = main:application  
socket = 127.0.0.1:8881  
workers = 2  
threads = 4  
chdir = /opt/Nginx-Cache-Clean  
py-autoreload = 1  
daemonize = /var/log/uwsgi/uwsgi.log  
uid = www-data  
gid = www-data  
pidfile = /var/run/uwsgi.pid  
logto = /var/log/uwsgi/uwsgi-error.log  
plugins = python3  
virtualenv = /usr/local/  
logto = /var/log/uwsgi.log
```  
# Nginx Unit config example(nginx-unit-config.json file):
```
{  
  "listeners": {  
      "127.0.0.1:8881": {  
       "pass": "applications/nginx_cache_clean"  
     }  
   },  
  "applications": {  
    "nginx_cache_clean": {  
      "type": "python 3.11",  
      "processes": 4,  
      "user": "www-data",  
      "group": "www-data",  
      "working_directory": "/opt/Nginx-Cache-Clean",  
      "home": "/usr/local/",  
      "path": "/usr/local/bin/",  
      "module": "main",  
      "callable": "application"  
    }
  }
}
```
  
and command to push it(bash script file):  
```
#!/bin/env bash  
  
curl -X PUT --data-binary @nginx-unit-config.json --unix-socket /var/run/control.unit.sock http://localhost/config  
```
# Gunicorn settings  
-Systemd unit (for example: /etc/systemd/system/gunicorn-nginx-cache-clean.service). Change to yours:
```
[Unit]
Description=Gunicorn instance for Nginx-Cache-Clean
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/Nginx-Cache-Cleaner
Environment="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/usr/bin/gunicorn -c /opt/Nginx-Cache-Cleaner/gunicorn_config.py main:application
StandardOutput=append:/var/log/gunicorn/nginx-cache-clean.log
StandardError=append:/var/log/gunicorn/nginx-cache-clean-error.log

[Install]
WantedBy=multi-user.target
```
-Gunicorn file(gunicorn_config.py, not tracked in git - create it on the server). Change to yours if anything:  
```
import sys
import os

#change to yours
venv_path = "/usr/local/"
sys.path.insert(0, os.path.join(venv_path, "lib/python3.11/site-packages"))
#change to yours
sys.path.insert(0, "/opt/Nginx-Cache-Cleaner")

bind = "127.0.0.1:8880"
workers = 3
timeout = 30
loglevel = "info"
wsgi_app = "main:application"

```

# Dependencies
Flask, Flask-SQLAlchemy, Flask-Login, Werkzeug, httpx, click, gunicorn (or uwsgi).

# Upgrading from the pre-refactor single-file version
The database file path (`/etc/nginx_cache_clean/nginx_cache_clean.db`) is unchanged, so existing
installs keep their data. On first start after upgrading, the app automatically adds the new
`rights` (users) and `autheliaLogoutUrl` (settings) columns to the existing database - no manual
migration needed. Update your uwsgi/gunicorn/systemd configuration to point at `main:application`
instead of `nginx_cache_clean:application` (see examples above).
