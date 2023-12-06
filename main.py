# Standard
import os
import secrets
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

# Risk
import numpy as np
import pandas as pd

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI(
    title="Financial Toolkit API",
    summary="Backend of the Financial Toolkit Demo",
)

origins = [
    "http://localhost:3000",
    "https://chris-kc-cheng.github.io"
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
ACCESS_TOKEN_EXPIRE_DAYS = 30


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


@app.get("/user", response_model=User)
async def user_profile(
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


class Note(BaseModel):
    id: PyObjectId = Field(alias="_id", default=None)
    authorId: PyObjectId
    authorName: str
    fundId: PyObjectId
    fundName: str
    modifiedDate: datetime
    content: str
    published: bool


class UpdateNote(BaseModel):
    content: str
    published: bool


@app.post("/fund",
          response_model=Fund)
async def create_new_fund(req: Annotated[Fund, Body()]):
    result = await db.fund.insert_one(
        req.model_dump(by_alias=True, exclude=['id'])
    )
    created_fund = await db.fund.find_one(
        {"_id": result.inserted_id}
    )
    return created_fund


@app.get("/fund", response_model=list[Fund])
async def get_all_funds():
    return await db.fund.find({}).collation({'locale': 'en'}).sort({'name': 1}).to_list(1000)


@app.get("/fund/{id}", response_model=Fund)
async def get_fund_details(id: str):
    return await db.fund.find_one({'_id': ObjectId(id)})


@app.get("/fund/{id}/note", response_model=list[Note])
async def get_fund_notes(id: str):
    """Including draft"""
    return await db.note.find({'fundId': ObjectId(id)}).sort({'modifiedDate': -1}).to_list(1000)


@app.get("/note", response_model=list[Note])
async def get_published_notes(skip: int = 0, limit: int = 1):
    return await db.note.find({'published': True}).sort({'modifiedDate': -1}).skip(skip).limit(limit).to_list(limit)


@app.get("/note/{id}", response_model=Note)
async def get_note(id):
    return await db.note.find_one({'_id': ObjectId(id)})


@app.post("/note/{fund_id}", response_model=Note)
async def post_new_note(
    fund_id: str,
    current_user: Annotated[User, Depends(get_current_user)]
):
    # fund is a dict, not Fund object
    fund = await get_fund_details(fund_id)
    result = await db.note.insert_one({
        'authorId': current_user.id,
        'authorName': current_user.first_name + ' ' + current_user.last_name,
        'fundId': fund['_id'],
        'fundName': fund['name'],
        'modifiedDate': datetime.now(),
        'content': '',
        'published': False
    })
    created_note = await db.note.find_one(
        {"_id": result.inserted_id}
    )
    return created_note


@app.put("/note/{id}", response_model=Note)
async def save_note(id: str, update: UpdateNote):
    # TODO: Check user is the original author
    await db.note.update_one({'_id': ObjectId(id)}, {'$set': {
        'content': update.content,
        'published': update.published,
        'modifiedDate': datetime.now()
    }})
    updated_note = await db.note.find_one(
        {"_id": ObjectId(id)}
    )
    return updated_note


@app.get("/risk/test")
def test_data_for_charts():
    """
    Line/Bar/Scatter chart:
        dict of 3 lists: index, columns and data
    Pie chart:
        dict of 2 lists: columns and data
    Scatter chart:
    """
    line = pd.DataFrame(np.random.randint(0, 100, size=(10, 2)),
                        columns=['Fund', 'Benchmark'],
                        index=pd.date_range(start='2000-01-01', freq='M', periods=10))
    line.index = line.index.to_series().astype(str)

    scatter = pd.DataFrame(np.random.randint(0, 100, size=(3, 2)), index=[
                           'Fund', 'Benchmark', 'Peer Group'], columns=['Return', 'Volatility'])

    bar = pd.DataFrame(np.random.randint(0, 100, size=(5, 3)),
                       columns=['US/Canada', 'Europe', 'Asia'],
                       index=pd.period_range(start='2023-01', freq='M', periods=5))
    bar.index = bar.index.astype(str)

    pie = pd.Series(np.random.randint(0, 100, size=(3)), index=[
                    'Equity', 'Fixed Income', 'Cash']).to_dict()

    return {
        'lineChartData': line.to_dict(orient='split'),
        'scatterChartData': scatter.to_dict(orient='split'),
        'barChartData': bar.to_dict(orient='split'),
        'pieChartData': {
            'columns': list(pie),
            'data': list(pie.values())
        }
    }
