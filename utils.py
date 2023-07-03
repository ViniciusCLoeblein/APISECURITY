import cx_Oracle
from dotenv import load_dotenv
import os
from fastapi import HTTPException

load_dotenv()
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
con = cx_Oracle.connect(f"{DB_USER}/{DB_PASSWORD}@{DB_HOST}")

def upsert_token(id: int, token: str, user: str):
    cursor = con.cursor()
    rows = cursor.execute(
            "SELECT * FROM acess_token " +
            " WHERE id_user = :id_user ",
            {"id_user": id}
        ).fetchall()
    if (len(rows) > 0):
        cursor.execute(
            "UPDATE acess_token " +
            "SET token = :token, name_user = :name_user " +
            "WHERE id_user = :id_user",
            {"id_user": id, "token": token, "name_user": user}
        )
    else:
        cursor.execute(
            "INSERT INTO acess_token (id_user, token, name_user) " +
            "VALUES (:id_user, :token, :name_user)",
            {"id_user": id, "token": token, "name_user": user}
        )
    con.commit()
    cursor.close()
    return


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
    raise HTTPException(status_code=401, detail="Token inválido, faça login para continuar!")

def verify_client(id: int, client: str):
    if CLIENT_SECRET == client and CLIENT_ID == id:
        return True
    raise HTTPException(status_code=401, detail="Cliente inválido, utilize um cliente válido para prosseguir!")