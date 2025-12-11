from PathsImports import *

def check_validation(email: str, password: str) -> bool:
    return cliente.validate(password, email)

def encrypt_password(password: str) -> str:
    print(CLI.Fore.GREEN + "Dados válidos")
    cifra_rsa = CLI.rsa.carregar_chave_publica()
    password_enc = cifra_rsa.encrypt(password.encode())
    password_cifrada = base64.b64encode(password_enc).decode()
    print (CLI.Fore.GREEN + "Password cifrada com sucesso")
    return password_cifrada

def set_user_path (email: str) -> str:
    os.makedirs(DB_DIR, exist_ok=True)
    safe_name = email.replace("@", "_at_").replace(".", "_dot_")
    user_path = os.path.join(DB_DIR, safe_name)
    os.makedirs(user_path, exist_ok=True)
    return user_path

def get_token_path(email: str) -> str:
    os.makedirs(TOKEN_DIR, exist_ok=True)
    safe_name = email.replace("@", "_at_").replace(".", "_dot_")
    return os.path.join(TOKEN_DIR, f"{safe_name}.token")

def save_token(email: str, token: str):
    path = get_token_path(email)
    with open(path, "w") as f:
        f.write(token)

def load_token(email: str) -> str:
    path = get_token_path(email)
    if not os.path.exists(path):
        raise Exception(f"Utilizador '{email}' não autenticado. Faz login primeiro.")
    with open(path, "r") as f:
        return f.read().strip()
    
def get_stored_nonce(email: str) -> str:
    safe_name = email.replace("@", "_at_").replace(".", "_dot_")
    nonce_path = os.path.join(TOKEN_DIR, f"{safe_name}.nonce")
    
    if not os.path.exists(nonce_path):
        typer.echo(f"Nonce não encontrado para {email}. Execute 'request_nonce {email}' primeiro.")
        sys.exit(1)
    
    with open(nonce_path, "r") as f:
        nonce = f.read().strip()
    os.remove(nonce_path)
    return nonce