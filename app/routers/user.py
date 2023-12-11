import os
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, ConfigDict, Field
from typing_extensions import Annotated
from bson import ObjectId
from ..dependencies import db, PyObjectId

router = APIRouter(prefix='/user',
                   tags=['user'],
                   dependencies=[],
                   responses={404: {'description': 'Not found'}})

SECRET_KEY = os.environ["SECRET_KEY"]
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="user/login")


class Message(BaseModel):
    status: str
    message: str


class ChangePassword(BaseModel):
    old_password: str
    new_password: str
    confirm_password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    id: PyObjectId = Field(alias="_id", default=None)
    username: str
    password: str | None = None
    first_name: str = Field(alias="firstName")
    last_name: str = Field(alias="lastName")
    is_active: bool = Field(alias="isActive", default=True)
    roles: list[str] = ['user']
    followed: list[PyObjectId] = []

    model_config = ConfigDict(
        populate_by_name=True)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


async def get_user(username: str):
    try:
        user = await db.user.find_one({'username': username, 'isActive': True})
        return User(**user)
    except Exception as e:
        return False


async def authenticate_user(username: str, password: str):
    user = await get_user(username)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


@router.post("/login", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    print('token')
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
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
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = await get_user(token_data.username)
    if user is None:
        raise credentials_exception
    return user


class RoleRequired:
    def __init__(self, role: str):
        self.role = role

    def __call__(self, user: Annotated[User, Depends(get_current_user)]):
        return self.role in user.roles


admin_required = RoleRequired("admin")


@router.get("/", response_model=User)
async def user_profile(
    current_user: Annotated[User, Depends(get_current_user)]
):
    return current_user.model_dump(by_alias=True, exclude=['password'])


@router.put("/password", response_model=Message)
async def user_change_password(
    request: ChangePassword,
    current_user: Annotated[User, Depends(get_current_user)]
):
    if not verify_password(request.old_password, current_user.password):
        return {'status': 'error', 'message': 'Cannot verify'}
    if request.new_password != request.confirm_password:
        return {'status': 'error', 'message': 'Passwords do not match'}
    await db.user.update_one({'_id': ObjectId(current_user.id)}, {'$set': {'password': get_password_hash(request.new_password)}})
    return {'status': 'success', 'message': 'Password changed successfully'}
