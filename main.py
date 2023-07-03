from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
import cx_Oracle
import auth.login as login
from utils import con

app = FastAPI()
# cx_Oracle.init_oracle_client(lib_dir=r"C:\instantclient_21_6")
origins = [
    "http://localhost:5173",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return RedirectResponse(url="/docs")

app.include_router(login.router)