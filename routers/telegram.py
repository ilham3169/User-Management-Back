from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy.orm import Session
from schemas import TelegramMessage
from dotenv import dotenv_values
from datetime import datetime, timedelta, timezone
from database import SessionLocal

import pytz
import requests

env = dotenv_values(".env")

router = APIRouter(
    tags=["telegram"]
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

BOT_TOKEN = env["BOT_TOKEN"]
CHAT_ID = env["CHAT_ID"]

@router.post("/telegram/send-message")
def send_message(message: TelegramMessage):

    text = message.dict()


    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    data = {
        "chat_id": CHAT_ID,
        "text": text["message"],
        "parse_mode": "HTML"
    }

    requests.post(url, json=data)
    return {"status": "sent"}
