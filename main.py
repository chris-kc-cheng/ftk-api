# Standard
import os, secrets
from datetime import date, datetime, timedelta
from enum import Enum
from typing_extensions import Annotated

# FastAPI/Pydantic
from fastapi import FastAPI, Body, Depends, Query, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import ConfigDict, BaseModel, Field, EmailStr, conlist
from pydantic.functional_validators import BeforeValidator

# Security
from jose import JWTError, jwt
from passlib.context import CryptContext

# Database
from bson import ObjectId
import motor.motor_asyncio

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI(
    title="Financial Toolkit API",
    summary="Backend of the Financial Toolkit Demo",
)

origins = [
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = motor.motor_asyncio.AsyncIOMotorClient(os.environ["MONGODB_HOST"])
db = client.ftkdb

PyObjectId = Annotated[str, BeforeValidator(str)]

SECRET_KEY = os.environ["SECRET_KEY"]
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


@app.get("/")
async def root():
    return {'message': 'success'}


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


@app.post("/token", response_model=Token)
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
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
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


@app.get("/user", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_user)]
):
    return current_user.model_dump(by_alias=True, exclude=['password'])


class ChangePassword(BaseModel):
    old_password: str
    new_password: str
    confirm_password: str

class ResetPassword(BaseModel):
    username: str
    password: str = secrets.token_urlsafe

class Message(BaseModel):
    status: str
    message: str

@app.put("/user/password", response_model=Message)
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

@app.post("/user",
          response_model=User)
async def create_user(user: Annotated[User, Body()]):
    result = await db.user.insert_one(
        user.model_dump(by_alias=True, exclude=['id', 'password'])
    )
    created_user = await db.user.find_one(
        {"_id": result.inserted_id}
    )
    return created_user

@app.put("/user/reset",
          response_model=Message)
async def reset_user_password(req: Annotated[ResetPassword, Body()]):
    result = await db.user.update_one(
        {'username': req.username},
        {'$set': {'password': get_password_hash(req.password)}}
    )
    if result.modified_count == 1:
        return {'status': 'success', 'message': 'Password is reset'}
    else:
        return {'status': 'error', 'message': 'User not found'}
    
class Fund(BaseModel):
    id: PyObjectId = Field(alias="_id", default=None)
    name: str = Field(min_length=1)
    firm: str = Field(min_length=1)
    assetClasses: conlist(str, min_length=1)
    launchDate: date | None = None

@app.post("/fund",
          response_model=Fund)
async def create_new_fund(req: Annotated[Fund, Body()]):    
    print("AAA", req, req.model_dump(by_alias=True, exclude=['id']))
    result = await db.fund.insert_one(
        req.model_dump(by_alias=True, exclude=['id'])
    )
    print("BBB", result)
    created_fund = await db.fund.find_one(
        {"_id": result.inserted_id}
    )
    print("CCC")
    return created_fund

@app.get("/fund", response_model=list[Fund])
async def get_funds():
    return await db.fund.find({}).collation({'locale':'en'}).sort('name').to_list(1000)


@app.get("/fund/{id}", response_model=Fund)
async def get_fund(id: str):
    return await db.fund.find_one({'_id': id})


"""
@bp_fund.route('/<id>')
@flask_praetorian.auth_required
def get_fund(id):
    print('Fund Details')
    fund = Fund.objects.get(pk=id)
    return jsonify(fund), 200


@bp_fund.route('/<id>/note')
@flask_praetorian.auth_required
def get_fund_notes(id):
    '''All notes including drafts'''
    notes = Note.objects(fundId=id).order_by('-modifiedDate')
    return jsonify(notes), 200
"""