import secrets
import logging
from sqlalchemy.orm import sessionmaker
from fastapi import FastAPI, Depends, HTTPException, status, Body, APIRouter
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import List, Generator
from models import (Message, database, engine, chat, Role, UserOut,
                    UserInDB, get_password_hash, verify_password, User, UserResponse, LoginUser,
                    MessageContent, MessageDelete, MessageUpdate)


logging.basicConfig(level=logging.INFO)


SECRET_KEY = secrets.token_hex(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Загрузка пользователей (псевдоданные)
fake_users_db = {}

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
router = APIRouter()
app.include_router(router)

Session = sessionmaker(bind=engine)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
session = Session()


# Функция для создания нового пользователя
def create_user(user: User):
    if user.username in fake_users_db:
        raise HTTPException(status_code=400, detail="Username already registered")

    hashed_password = get_password_hash(user.password)
    user = UserInDB(
        username=user.username,
        full_name=user.full_name,
        email=user.email,
        hashed_password=get_password_hash(user.password),
        disabled=user.disabled,
        role=user.role
    )
    session.add(user)
    session.commit()
    print(f"Пользователь с именем {user.username} зарегестрировался")
    session.refresh(user)


# Эндпоинт для регистрации нового пользователя
@app.post("/register", response_model=User)
async def register(user: User):
    create_user(user)
    return user


# Эндпоинт для получения всех пользователей в чате
@app.get("/users", response_model=List[UserResponse])
def get_users():
    query = session.query(UserInDB).all()
    list_query_dict = []
    for q in query:
        query_dict = {
            'username': q.username,
            'full_name': q.full_name,
            'email': q.email,
            'hashed_password': q.hashed_password,
            'disabled': q.disabled,
            'role': q.role
          }
        list_query_dict.append(query_dict)
    return list_query_dict


@app.on_event("startup")
async def startup():
    await database.connect()


@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()


# Функция для создания токенв
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now() + expires_delta
    else:
        expire = datetime.now() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Функция для получения текущего пользователя
def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = session.query(UserInDB).filter(UserInDB.username == username).first()
    if user is None:
        raise credentials_exception
    return user


def get_db_session() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        logging.info(f"Session created: {db}")
        yield db
    finally:
        logging.info("Closing database session.")
        db.close()


# Эндпоинт для блокировки/разблокировки пользователя
@app.put("/{block_or_unblock}/{user_id}", response_model=UserOut)
def block_user(user_id: int, block_or_unblock: str, token: str = Depends(oauth2_scheme)):
    """
    Route для блокировки пользователя по его user_id
    Проверяет, является ли текущий пользователь модератором, и блокирует пользователя, если возможно.
    """

    current_user = get_current_user(token)
    logging.info(f"Попытка заблокировать пользователя с id {user_id} модератором  {current_user.username}")
    # Проверка, что текущий пользователь - модератор
    if current_user.role != Role.MODERATOR:
        logging.info(f"Пользователь  {current_user.username} не имеет разрешения блокировать пользователей.")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")

    # Поиск пользователя по user_id
    user_to_block = session.query(UserInDB).filter(UserInDB.id == user_id).first()
    if not user_to_block:
        raise HTTPException(status_code=404, detail="User not found")

    # Логика блокировки пользователя
    if block_or_unblock == 'block_user':
        user_to_block.disabled = True
        session.commit()  # Сохраняем изменения в БД
        session.refresh(user_to_block)  # Обновляем данные о пользователе
        print(f"Пользователь с id {user_id} был заблокирован")
        return {"id": user_to_block.id,
                "username": user_to_block.username,
                "email": user_to_block.email,
                "is_active": False,
                "role": user_to_block.role}
    elif block_or_unblock == 'unblock_user':
        user_to_block.disabled = False
        session.commit()  # Сохраняем изменения в БД
        session.refresh(user_to_block)  # Обновляем данные о пользователе
        print(f"Пользователь с id {user_id} был разаблокирован")
        return {"id": user_to_block.id,
                "username": user_to_block.username,
                "email": user_to_block.email,
                "is_active": True,
                "role": user_to_block.role}


# Эндпоинт для входа в чат по логину и паролю
@app.post("/login")
async def login(user: LoginUser = Body(...)):
    db_user = session.query(UserInDB).filter(UserInDB.username == user.username).first()
    if db_user is None or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": db_user.username}, expires_delta=access_token_expires)
    if db_user.disabled == True:
        return {"Ошибка": "Вы были заблокированы"}
    else:
        return {"access_token": access_token, "token_type": "bearer"}


# Эндпоинт для отправки сообщения
@app.post("/messages/", response_model=Message)
def send_message(message_content: MessageContent, current_user: UserInDB = Depends(get_current_user)):
    message = Message(content=message_content.content)
    message.user = current_user.username
    chat.add_message(message)
    return message


# Эндпоинт для получения сообщений пользователей
@app.get("/messages/", response_model=List[Message])
def read_messages(current_user: UserInDB = Depends(get_current_user)):
    return chat.get_messages()


# Эндпоинт для удаления сообщений
@app.delete("/messages/", response_model=List[Message])
def remove_messages(message_delete: MessageDelete, current_user: UserInDB = Depends(get_current_user)):
    return chat.delete_messages(message_delete.id)


# Эндпоинт для редактирования сообщений
@app.put("/messages/", response_model=List[Message])
def change_messages(message_update: MessageUpdate, current_user: UserInDB = Depends(get_current_user)):
    messages = chat.get_messages()
    flag = False
    for i, message in enumerate(messages):
        if message["user"] == current_user.username and message_update.id == message["id"]:
            flag = True
    if flag:
        return chat.update_messages(message_update.dict())
    else:
        return {"response": "Невозможно редактировать сообщение другого пользователя"}
