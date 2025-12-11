import typer
import httpx
import base64
import os
import sys
import json
import secrets
import getpass
import socket
import mimetypes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

API_URL = "https://localhost:8443"
TOKEN_DIR = ".tokens"
DB_DIR = "DB_USERS"
TOKEN_PATH = "token.txt"
CA_CERT_PATH = "../certs/ca.crt"
ACTIVE_SESSION_FILE = ".active_session"
TERMINAL_BASE_DIR = os.path.join(os.path.expanduser("~"), ".client_terminals")
TERMINAL_ID_FILE = os.path.join(TERMINAL_BASE_DIR, "current_terminal_id.txt")
SESSIONS_DIR = os.path.join(os.path.expanduser("~"), ".client_sessions")

implementacao_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'P1'))
sys.path.append(implementacao_path)

import CLI
cliente = CLI.Client()


app = typer.Typer()