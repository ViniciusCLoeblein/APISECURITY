from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Annotated
from fastapi.responses import JSONResponse
import jwt
import datetime
from models import Register_user
from passlib.hash import bcrypt
from utils import con, verify_token, upsert_token, verify_client
from dotenv import load_dotenv
import os

load_dotenv()
CLIENT_ALGORITHM = os.getenv("CLIENT_ALGORITHM")

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="autenticar")

@router.post("/autenticar")
def autenticar(obj: OAuth2PasswordRequestForm = Depends()):
    try:
        client = verify_client(obj.client_id, obj.client_secret)
        if not client:
            raise HTTPException(status_code=401, detail="Cliente inválido, utilize um cliente válido para prosseguir!")
        cursor = con.cursor()
        cursor.execute(
            "SELECT * FROM usuarios " +
            "WHERE name = :name",
            {"name": obj.username}
        )
        row = cursor.fetchone()

        if row:
            stored_password = row[2]
            if bcrypt.verify(obj.password, stored_password):
                payload = {
                    "id": row[0],
                    "nome": row[1],
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7)
                }
                token = jwt.encode(payload, obj.client_secret, algorithm=CLIENT_ALGORITHM)
                user = upsert_token(row[0])

                if not user:
                    cursor.execute(
                        "INSERT INTO acess_token (id_user, token, name_user) " +
                        "VALUES (:id_user, :token, :name_user)",
                        {"id_user": row[0], "token": token, "name_user": row[1]}
                    )
                else:
                    cursor.execute(
                        "UPDATE acess_token " +
                        "SET token = :token, name_user = :name_user " +
                        "WHERE id_user = :id_user",
                        {"id_user": row[0], "token": token, "name_user": row[1]}
                    )

                con.commit()
                cursor.close()

                response_payload = {
                    "id": row[0],
                    "nome": row[1],
                    "access_token": token
                }
                response = JSONResponse(content=response_payload)
                response.set_cookie(key="LOGIN_INFO", value=token)

                return response

        raise HTTPException(status_code=401, detail="Credenciais inválidas")
    except HTTPException as ex:
        raise ex
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))

    
@router.post("/register-user")
def register_user(obj: Register_user):
    try:
        cursor = con.cursor()
        cursor.execute("SELECT name from usuarios " + 
                       "WHERE name = :name",
                       {"name": obj.name }
                       )
        verify_name = cursor.fetchone()
        print(verify_name)
        if verify_name is None:
            cursor.execute("SELECT seq_usuario.NEXTVAL FROM DUAL")
            seq = cursor.fetchone()[0]
            password_hash = bcrypt.hash(obj.password)

            cursor.execute(
                "INSERT INTO usuarios (id, name, password) " +
                "VALUES (:id, :name, :password) ",
                {"id": seq, "name": obj.name, "password": password_hash }
            )
            con.commit()
            cursor.close()
            return {
                    "status": "ok",
                    "id": seq
                }
        return "Usuario já existente!"
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))   

@router.get("/usuario")
def usuarios(token: Annotated[str, Depends(oauth2_scheme)]):
    try:
        user = verify_token(token)
        if not user:
            raise HTTPException(status_code=401, detail="Token inválido, faça login para continuar!")
        cursor = con.cursor()
        rows = cursor.execute(
            "SELECT * FROM usuarios where id=:id",{"id": user}
        ).fetchall()
        cursor.close()

        for r in rows:
            payload = {
                "id": r[0],
                "nome": r[1],
            }
            response = JSONResponse(content=payload)
            response.set_cookie(key="teste", value="teste")
            return payload

    except HTTPException as ex:
        raise ex

    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))
    