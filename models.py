import json
from sqlalchemy import create_engine, Column, String, Boolean, Integer, Enum
from sqlalchemy.ext.declarative import declarative_base
from config import config
from pydantic import BaseModel
from typing import Optional
from passlib.context import CryptContext
from datetime import datetime
import databases
from enum import Enum as PyEnum

database = databases.Database(config.DATABASE_URI)
Base = declarative_base()
engine = create_engine(config.DATABASE_URI)


class Role(PyEnum):
    # Роли пользователей
    USER = "user"
    MODERATOR = "moderator"
    ADMIN = "admin"


class User(BaseModel):
    # Класс для создания пользователей
    username: str
    password: str
    full_name: Optional[str] = None
    email: Optional[str] = None
    disabled: Optional[bool] = None
    role: str


class UserOut(BaseModel):
    # Запрос для блокировки/разблокировки пользователей
    id: int
    username: str
    email: str
    is_active: bool
    role: Role

    class Config:
        orm_mode = True


class UserResponse(BaseModel):
    # Запрос для получения списка пользователей в чате
    username: str
    full_name: Optional[str] = None
    email: Optional[str] = None
    disabled: bool


class UserInDB(Base):
    # Класс для записи пользователей в БД
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    full_name = Column(String, index=True, nullable=True)
    email = Column(String, index=True, nullable=True)
    hashed_password = Column(String)
    disabled = Column(Boolean, default=False)
    role = Column(Enum(Role), default=Role.USER)


Base.metadata.create_all(bind=engine)


class LoginUser(BaseModel):
    # Класс для входа пользователей
    username: str
    password: str


# Для хеширования паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    print("Hashing password:", password)
    return pwd_context.hash(password)


# Чат сообщения
class Message(BaseModel):
    # Параметры сообщений
    id: Optional[int] = None
    user: Optional[str] = None
    content: str
    timestamp: datetime = datetime.now()


class MessageContent(BaseModel):
    # Класс по отправке сообщений
    content: str


class MessageDelete(BaseModel):
    # Класс по удалению сообщений
    id: int


class MessageUpdate(BaseModel):
    # Класс по редактированию сообщений
    id: int
    new_message: str

class Chat:
    def __init__(self):
        self.messages = self.load_messages()
        if self.messages:
            self.next_id = max(message["id"] for message in self.messages) + 1
        else:
            self.next_id = 1

    def load_messages(self):
        try:
            with open('messages.json', 'r') as file:
                data = json.load(file)
                return data["data"]
        except Exception:
            return []

    def save_message(self, messages):
        with open('messages.json', 'w') as file:
            json.dump({"data": messages}, file, default=str)

    def add_message(self, message: Message):
        message.id = self.next_id
        self.messages.append(message.dict())
        self.save_message(self.messages)
        self.next_id += 1

    def get_messages(self):
        return self.messages

    def delete_messages(self, message_id: int):
        self.messages = [msg for msg in self.messages if msg['id'] != message_id]
        self.save_message(self.messages)
        return self.messages

    def update_messages(self, content: dict):
        messages = self.get_messages()
        for message in messages:
            if message['id'] == content['id']:
                message['content'] = content['new_message']
        self.save_message(self.messages)
        return messages


chat = Chat()
