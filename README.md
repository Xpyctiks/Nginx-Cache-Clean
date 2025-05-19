-Python web application with CLI functions allows to purge Nginx folders with cached files.  
-Uses sqlite3 DB to store options.  
-User management and cache path management via CLI.  
-Bulk import of cahce pathes from file in simple format:  
<name> <path>  
-Security variable CACHE_FOLDER_BEGIN_WITH which used to confirm you are not purging the root folder in any way  
-Sending important alerts or notoification to Telegram if ChatID and Token are set.  
