import logging
import httpx
import threading
from flask import current_app

def send_to_telegram_func(message: str, subject: str = "Nginx-Cache-Clean", chatid: str = "", token: str = "") -> None:
  """Sends a message via Telegram if both chatid and token are set. Runs synchronously - call via send_to_telegram() instead."""
  try:
    if not chatid or not token:
      logging.info("Telegram ChatID or/and Token is not set...")
      return
    data = {
      "chat_id": chatid,
      "text": f"{subject}\n{message}",
    }
    with httpx.Client(timeout=5) as client:
      response = client.post(f"https://api.telegram.org/bot{token}/sendMessage", json=data)
      if response.status_code != 200:
        logging.error(f"Telegram bot error! Status: {response.status_code} Body: {response.text}")
  except Exception as err:
    logging.error(f"Error while sending message to Telegram: {err}")

def send_to_telegram(message: str, subject: str = "Nginx-Cache-Clean"):
  """Fires off the Telegram notification in a background thread so requests never block on it."""
  chatid = current_app.config.get("TELEGRAM_CHATID", "")
  token = current_app.config.get("TELEGRAM_TOKEN", "")
  threading.Thread(target=send_to_telegram_func, args=(message, subject, chatid, token), daemon=True).start()
