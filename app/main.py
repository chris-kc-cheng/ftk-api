# Standard
import os

# FastAPI/Pydantic
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# FastAPI Routers
from .internal import admin
from .routers import user
from .routers import fund
from .routers import note
from .routers import risk
from .routers import market

app = FastAPI(
    title="Financial Toolkit API",
    summary="Backend of the Financial Toolkit Demo",
)

app.include_router(admin.router)
app.include_router(user.router)
app.include_router(fund.router)
app.include_router(note.router)
app.include_router(risk.router)
app.include_router(market.router)

origins = [
    "http://127.0.0.1:3000",
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


@app.get("/")
async def root():
    return {'message': 'success'}
