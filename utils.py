import cx_Oracle
from dotenv import load_dotenv
import os

load_dotenv()
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
con = cx_Oracle.connect(f"{DB_USER}/{DB_PASSWORD}@{DB_HOST}")

def upsert_token(id: int):
    cursor = con.cursor()
    rows = cursor.execute(
            "SELECT * FROM acess_token " +
            " WHERE id_user = :id_user ",
            {"id_user": id}
        ).fetchall()
    print(rows)
    if (len(rows) > 0):
        return True
    return False


def verify_token(token: str):
    cursor = con.cursor()
    rows = cursor.execute(
            "SELECT * FROM acess_token " +
            " WHERE token = :token ",
            {"token": token}
        ).fetchall()
    for r in rows:
        access_token = r[1]
        if token == access_token:
            return r[0]
        return False

def verify_client(id: int, client: str):
    if CLIENT_SECRET == client and CLIENT_ID == id:
        return True
    return False