import logging
from db.db import db
from db.database import CachePath

def add_cache(name: str, path: str) -> None:
  """CLI only function: adds a new cache path entry"""
  logging.info("-----------------------Starting CLI functions: add_cache")
  try:
    new_cache = CachePath(cacheName=name, cachePath=path)
    db.session.add(new_cache)
    db.session.commit()
    print(f"Cache path \"{name}\" - \"{path}\" added successfully.")
    logging.info(f"cli>Cache path \"{name}\" - \"{path}\" added successfully.")
  except Exception as err:
    logging.error(f"cli>Add cache error: {err}")
    print(f"Add cache error: {err}")
    quit(1)

def del_cache(name: str) -> None:
  """CLI only function: deletes an existing cache path entry"""
  logging.info("-----------------------Starting CLI functions: del_cache")
  entry = CachePath.query.filter_by(cacheName=name).first()
  if not entry:
    print(f"Cache \"{name}\" delete error - no such entry!")
    logging.error(f"cli>Cache \"{name}\" delete error - no such entry!")
    quit(1)
  path = entry.cachePath
  db.session.delete(entry)
  db.session.commit()
  print(f"Cache \"{name}\" - \"{path}\" deleted successfully.")
  logging.info(f"cli>Cache \"{name}\" - \"{path}\" deleted successfully.")

def show_cache() -> None:
  """CLI only function: shows all cache path entries"""
  cache_settings = CachePath.query.order_by(CachePath.cacheName).all()
  for s in cache_settings:
    print(f"{s.cacheName} - {s.cachePath}")

def import_cache(file: str) -> None:
  """CLI only function: bulk-imports cache path entries from a "<name> <path>" per-line text file"""
  logging.info("-----------------------Starting CLI functions: import_cache")
  try:
    with open(file, 'r', encoding='utf8') as f:
      for line in f:
        stripped = line.strip()
        if not stripped:
          continue
        parts = stripped.split(maxsplit=1)
        if len(parts) != 2:
          print(f"Incorrect line skipped: {line}")
          continue
        name, path = parts
        db.session.add(CachePath(cacheName=name, cachePath=path))
    db.session.commit()
    print("Bulk cache settings loaded from file successfully.")
    logging.info(f"cli>Bulk cache settings loaded successfully from {file}.")
  except Exception as err:
    logging.error(f"cli>Bulk cache loading error: {err}")
    print(f"Bulk cache loading error: {err}")
    quit(1)
