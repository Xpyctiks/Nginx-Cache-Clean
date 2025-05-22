-Python web application with CLI functions allows to purge Nginx folders with cached files.  
-Uses sqlite3 DB to store options.  
-User management and cache path management via CLI.  
-Bulk import of cahce pathes from file in simple format:  
<name> <path>  
-Security variable CACHE_FOLDER_BEGIN_WITH which used to confirm you are not purging the root folder in any way  
-Sending important alerts or notoification to Telegram if ChatID and Token are set.  

# UWSGI server config example:  
```
[uwsgi]  
module = nginx_cache_clean:application  
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
      "module": "nginx_cache_clean",  
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
Description=Gunicorn instance for nginx-cache-clean.py
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/Nginx-Cache-Cleaner
Environment="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/usr/bin/gunicorn -c /opt/Nginx-Cache-Cleaner/gunicorn_config.py nginx_cache_clean:application
StandardOutput=append:/var/log/gunicorn/nginx-cache-clean.log
StandardError=append:/var/log/gunicorn/nginx-cache-clean-error.log

[Install]
WantedBy=multi-user.target
```
-Gunicorn file(gunicorn_config.py).Change to yours if anything:  
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
wsgi_app = "nginx_cache_clean:application"

```