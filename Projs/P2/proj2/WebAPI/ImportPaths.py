from fastapi import FastAPI, HTTPException, Depends, Path
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict, Any
import os, sys, uuid, json, base64, time
from datetime import datetime, timedelta
import jwt  # pip install PyJWT
from argon2 import PasswordHasher
import uvicorn
import ssl
import shutil

implementacao_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'P1'))
sys.path.append(implementacao_path)
import SRV

server = SRV.ServerWorker()

# --- Inicialização da app ---
app = FastAPI(title="Secure Vault API")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
ph = PasswordHasher()

# --- Chave JWT secreta ---
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# --- Simular base de dados ---
USERS_DB = {}
USER_IDS = {}

NONCES: Dict[str, Dict[str, any]] = {}  # {email: {"nonce": value, "timestamp": time}}
NONCE_EXPIRY_SECONDS = 300  