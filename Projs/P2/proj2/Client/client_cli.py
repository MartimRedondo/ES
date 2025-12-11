from PathsImports import *
from session_helper import *
from register_helper import *
from OwnCrypto import *

def get_previous_shares(folder_name: str, email: str) -> dict:
    token = load_token(email)
    headers = {"Authorization": f"Bearer {token}"}
    keyname = f"{folder_name}/.metadata"
    try:
        #typer.echo(f"[DEBUG] A obter partilhas anteriores para '{keyname}'...")
        resp = httpx.get(f"{API_URL}/permissions", headers=headers, verify=CA_CERT_PATH)
        #typer.echo(f"[DEBUG] Resposta do /permissions: {resp.status_code}")
        if resp.status_code == 200:
            data = resp.json()
            shared = data.get(keyname, {})
            #typer.echo(f"[DEBUG] Partilhas encontradas: {shared}")
            return shared
        else:
            typer.echo(f"[ERRO] Falha ao obter partilhas: {resp.text}")
    except Exception as e:
        typer.echo(f"[ERRO] Exceção ao obter partilhas anteriores: {str(e)}")
    return {}

def share_metadata(folder_name: str, from_email: str, to_email: str, permissions: list):
    token = load_token(from_email)
    headers = {"Authorization": f"Bearer {token}"}
    metadata_path = f"{folder_name}/.metadata"

    #typer.echo(f"[DEBUG] A iniciar partilha de '{metadata_path}' com '{to_email}'...")

    try:
        # Partilhar o ficheiro .metadata
        success = share_file(metadata_path, from_email, to_email, permissions, headers)
        if success:
            typer.echo(f"  ✓ Metadata repartilhada com {to_email}")
        else:
            typer.echo(f"  ✗ Falha ao repartir metadata com {to_email}")

        # Obter lista de ficheiros da pasta
        #typer.echo(f"[DEBUG] A obter ficheiros de '{folder_name}' para partilhar...")
        metadata_resp = httpx.get(f"{API_URL}/read/{folder_name}/.metadata", headers=headers, verify=CA_CERT_PATH)
        if metadata_resp.status_code != 200:
            typer.echo(f"[ERRO] Falha ao ler metadata da pasta: {metadata_resp.status_code} - {metadata_resp.text}")
            return

        response_data = metadata_resp.json()
        encrypted_metadata = base64.b64decode(response_data["encrypted_file"])
        encrypted_key = base64.b64decode(response_data["encrypted_key"])

        private_key, _ = load_or_generate_rsa_keys(from_email)
        aes_key = decrypt_aes_key_with_rsa(encrypted_key, private_key)
        decrypted_metadata = decrypt_with_aes(encrypted_metadata, aes_key)
        metadata = json.loads(decrypted_metadata.decode())

        # Partilhar todos os ficheiros contidos
        for file_path in metadata.get("contents", {}):
            full_path = f"{folder_name}/{file_path}"
            #typer.echo(f"[DEBUG] A partilhar '{full_path}' com '{to_email}'...")
            success = share_file(full_path, from_email, to_email, permissions, headers)
            if success:
                typer.echo(f"  ✓ Partilhado: {file_path}")
            else:
                typer.echo(f"  ✗ Falha ao partilhar: {file_path}")

    except Exception as e:
        typer.echo(f"  ✗ Erro ao repartir pasta com {to_email}: {str(e)}")

@app.command()
def set_terminal(number: int):
    """Define o número deste terminal (use um número diferente para cada terminal físico)"""
    term_num_file = os.path.join(TERMINAL_BASE_DIR, "terminal_number.txt")
    os.makedirs(TERMINAL_BASE_DIR, exist_ok=True)
    
    with open(term_num_file, "w") as f:
        f.write(str(number))
    
    terminal_id = get_terminal_id()
    typer.echo(f"Terminal configurado com número {number}")
    typer.echo(f"ID completo do terminal: {terminal_id}")

@app.command()
def register(name: str, email: str, password: str):

    #validation = cliente.validate(name, email, password)
    validation = True  # ou validação real

    if validation:
        password_cifrada = encrypt_password(password)

        _, public_key = load_or_generate_rsa_keys(email)
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_b64 = base64.b64encode(public_key_pem).decode()

        data = {
            "name": name,
            "email": email,
            "password": password_cifrada,
            "public_key": public_key_b64
        }

        resp = httpx.post(f"{API_URL}/register", json=data, verify=CA_CERT_PATH)

        try:
            typer.echo(resp.json())
            set_user_path(email)
        except Exception:
            typer.echo(f"Erro {resp.status_code}: {resp.text}")
    else:
        typer.echo("Dados inválidos. Verifique o nome, email e password.")

# Comando: nonce
@app.command()
def nonce(email: str):
    data = {"email": email}
    try:
        resp = httpx.post(f"{API_URL}/nonce", json={"email": email}, verify=CA_CERT_PATH)
        if resp.status_code == 200:
            data = resp.json()
            nonce = data["nonce"]
            
            # Salvar o nonce temporariamente
            os.makedirs(TOKEN_DIR, exist_ok=True)
            nonce_path = os.path.join(TOKEN_DIR, f"{email.replace('@', '_at_').replace('.', '_dot_')}.nonce")
            with open(nonce_path, "w") as f:
                f.write(nonce)
            
            typer.echo(f"Nonce obtido para {email}. Pode realizar o login agora.")
        else:
            typer.echo(f"Erro ao solicitar nonce: {resp.status_code} - {resp.text}")
    except Exception as e:
        typer.echo(f"Erro ao solicitar nonce: {str(e)}")

# Comando: login
@app.command()
def login(email: str, password: str):
    #validated = cliente.validate(password, email)
    validated = True

    if validated:
        try:

            terminal_id = get_terminal_id()

            nonce = get_stored_nonce(email)
            password_cifrada = encrypt_password(password)
            
            credentials = f"{nonce}:{password_cifrada}"
            
            data = {
                "username": email,
                "password": credentials
            }
            resp = httpx.post(f"{API_URL}/login", json=data, verify=CA_CERT_PATH)
            
            if resp.status_code == 200:
                token = resp.json()["access_token"]
                save_token(email, token)
                set_active_session(email, terminal_id)
                typer.echo(f"Login bem-sucedido. Token guardado para {email}.")
            else:
                typer.echo(f"Erro no login: {resp.status_code} - {resp.text}")
        except Exception as e:
            typer.echo(f"Erro durante o login: {str(e)}")
    else:
        typer.echo("Dados inválidos. Verifique o email e password.")

@app.command()
def prune_sessions():

    if not os.path.exists(SESSIONS_DIR):
        typer.echo("Nenhuma sessão para limpar.")
        return
    
    removed = 0
    for filename in os.listdir(SESSIONS_DIR):
        if filename.startswith("session_") and filename.endswith(".txt"):
            path = os.path.join(SESSIONS_DIR, filename)
            with open(path, "r") as f:
                email = f.read().strip()
            token_path = get_token_path(email)
            if not os.path.exists(token_path):
                os.remove(path)
                typer.echo(f"🧹 Removida sessão inválida: {email} (ficheiro: {filename})")
                removed += 1
    
    if removed == 0:
        typer.echo("Nenhuma sessão inválida encontrada.")

# Commands extras de sesão
@app.command()
def whoami():
    terminal_id = get_terminal_id()
    email = get_active_session(terminal_id)
    
    if email:
        typer.echo(f"Logado como: {email}")
        typer.echo(f"Terminal ID: {terminal_id}")
    else:
        typer.echo(f"Nenhum usuário logado neste terminal (ID: {terminal_id})")

@app.command()
def active():
    terminal_id = get_terminal_id()
    active_email = get_active_session(terminal_id)
    if active_email:
        typer.echo(f"Utilizador ativo neste terminal: {active_email} (Terminal ID: {terminal_id})")
    else:
        typer.echo(f"Nenhum utilizador com sessão ativa neste terminal (Terminal ID: {terminal_id}).")

@app.command()
def sessions():
    list_active_sessions()

@app.command()
def logout():
    terminal_id = get_terminal_id()
    active_email = get_active_session(terminal_id)
    if active_email:
        clear_active_session(terminal_id)
        typer.echo(f"Sessão terminada para {active_email} neste terminal (ID: {terminal_id}).")
    else:
        typer.echo(f"Não existe sessão ativa neste terminal (ID: {terminal_id}).")

# Comando: list-files
@app.command()
def list_files():

    terminal_id = get_terminal_id()

    if not verify_active_session():
        return
    
    email = get_active_session(terminal_id)
    token = load_token(email)

    headers = {"Authorization": f"Bearer {token}"}
    resp = httpx.get(f"{API_URL}/files", headers=headers, verify=CA_CERT_PATH)

    if resp.status_code == 200:
        data = resp.json()

        files = data.get("files", [])
        if not files:
            typer.echo("Nenhum ficheiro encontrado.")
        else:
            typer.echo("Ficheiros disponíveis:")
            for f in files:
                typer.echo(f" - {f}")

        folders = data.get("folders", [])
        if not folders:
            typer.echo("Nenhuma pasta encontrada.")
        else:
            typer.echo("\nPastas disponíveis:")
            for folder in folders:
                typer.echo(f" - {folder}")
    else:
        typer.echo(f"Erro {resp.status_code}: {resp.text}")

# Comando: upload
@app.command()
def upload(path: str, folder_name: str = None):

    terminal_id = get_terminal_id()

    if not verify_active_session():
        return
    
    email = get_active_session(terminal_id)

    if not os.path.exists(path):
        typer.echo(f"Error: Path '{path}' not found")
        return
    
    try:
        # Load auth token
        token = load_token(email)
        headers = {"Authorization": f"Bearer {token}"}
        
        # Load or generate RSA keys
        _, public_key = load_or_generate_rsa_keys(email)
        
        # Check if path is a file or directory
        if os.path.isfile(path):
            # Single file upload
            filename = os.path.basename(path)
            encrypted_data = encrypt_file(path, public_key)
            
            if not encrypted_data:
                return
            
            data = {
                "filename": filename,
                "encrypted_file": encrypted_data["encrypted_file"],
                "encrypted_key": encrypted_data["encrypted_key"]
            }
            
            resp = httpx.post(f"{API_URL}/upload", json=data, headers=headers, verify=CA_CERT_PATH)
            
            if resp.status_code == 200:
                typer.echo(f"File '{filename}' uploaded successfully!")
            else:
                typer.echo(f"Error {resp.status_code}: {resp.text}")
        
        else:
            # Directory upload
            if folder_name is None:
                folder_name = os.path.basename(path)
            
            # Create metadata for the folder structure
            metadata = {"type": "folder", "contents": {}}
            uploaded_count = 0
            failed_count = 0
            
            # Process all files in the directory and subdirectories
            for root, _, files in os.walk(path):
                for file in files:
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, path)
                    
                    # Normalize path separators
                    rel_path = rel_path.replace("\\", "/")
                    
                    # Encrypt the file
                    encrypted_data = encrypt_file(full_path, public_key)
                    
                    if not encrypted_data:
                        failed_count += 1
                        continue
                    
                    # Add file to metadata
                    metadata["contents"][rel_path] = {
                        "type": "file",
                        "size": os.path.getsize(full_path),
                        "mime": get_file_mime_type(full_path)
                    }
                    
                    # Prepare upload data
                    file_path_for_server = f"{folder_name}/{rel_path}"
                    data = {
                        "filename": file_path_for_server,
                        "encrypted_file": encrypted_data["encrypted_file"],
                        "encrypted_key": encrypted_data["encrypted_key"]
                    }
                    
                    # Upload the file
                    resp = httpx.post(f"{API_URL}/upload", json=data, headers=headers, verify=CA_CERT_PATH)
                    
                    if resp.status_code == 200:
                        uploaded_count += 1
                        typer.echo(f"Uploaded: {rel_path}")
                    else:
                        failed_count += 1
                        typer.echo(f"Failed to upload {rel_path}: {resp.status_code} - {resp.text}")
            
            # Upload the metadata file
            metadata_str = json.dumps(metadata)
            
            # Generate AES key and encrypt metadata
            aes_key = generate_aes_key()
            encrypted_metadata = encrypt_with_aes(metadata_str.encode(), aes_key)
            encrypted_key = encrypt_aes_key_with_rsa(aes_key, public_key)
            
            # Encode for JSON transport
            encrypted_metadata_b64 = base64.b64encode(encrypted_metadata).decode()
            encrypted_key_b64 = base64.b64encode(encrypted_key).decode()
            
            # Upload metadata file
            metadata_data = {
                "filename": f"{folder_name}/.metadata",
                "encrypted_file": encrypted_metadata_b64,
                "encrypted_key": encrypted_key_b64
            }
            
            metadata_resp = httpx.post(f"{API_URL}/upload", json=metadata_data, headers=headers, verify=CA_CERT_PATH)
            
            if metadata_resp.status_code == 200:
                typer.echo(f"\nFolder '{folder_name}' uploaded successfully!")
                typer.echo(f"Total files: {uploaded_count + failed_count}")
                typer.echo(f"Successfully uploaded: {uploaded_count}")
                if failed_count > 0:
                    typer.echo(f"Failed to upload: {failed_count}")
            else:
                typer.echo(f"Error uploading folder metadata: {metadata_resp.status_code} - {metadata_resp.text}")
    
    except Exception as e:
        typer.echo(f"Error during upload: {str(e)}")
  

@app.command()
def write(server_filename: str, local_filepath: str):

    terminal_id = get_terminal_id()
    if not verify_active_session():
        return
    email = get_active_session(terminal_id)

    # Verificar se o arquivo/pasta local existe
    if not os.path.exists(local_filepath):
        typer.echo(f"Erro: Caminho local '{local_filepath}' não encontrado")
        return
    
    try:
        # Carregar token de autenticação
        token = load_token(email)
        headers = {"Authorization": f"Bearer {token}"}
        
        # Verificar se o item é um arquivo ou pasta no servidor (OWNER)
        resp_list = httpx.get(f"{API_URL}/files", headers=headers, verify=CA_CERT_PATH)
        resp_shared = httpx.get(f"{API_URL}/shared_write", headers=headers, verify=CA_CERT_PATH)

        if resp_list.status_code != 200 or resp_shared.status_code != 200:
            typer.echo("Erro ao listar ficheiros.")
            return

        file_list = resp_list.json()
        shared_list = resp_shared.json()

        #typer.echo(f"[DEBUG] Ficheiros do utilizador: {file_list}")
        #typer.echo(f"[DEBUG] Ficheiros partilhados consigo: {shared_list}")

        is_folder = False

        # Verificar se é pasta do utilizador ou partilhada
        if "folders" in file_list and server_filename in file_list["folders"]:
            is_folder = True
        elif "folders" in shared_list and server_filename in shared_list["folders"]:
            is_folder = True

        # Verificar se é ficheiro (local ou partilhado)
        has_access_to_file = (
            ("files" in file_list and server_filename in file_list["files"]) or
            ("files" in shared_list and server_filename in shared_list["files"])
        )

        # Normalizar
        normalized_filename = server_filename.replace("\\", "/").strip()
        shared_files = [f.replace("\\", "/").strip() for f in shared_list.get("files", [])]

        # Debug
        #typer.echo(f"[DEBUG] Nome procurado (normalizado): '{normalized_filename}'")
        #typer.echo(f"[DEBUG] Lista de ficheiros partilhados (normalizados): {shared_files}")

        is_shared = normalized_filename in shared_files

        #typer.echo(f"[DEBUG] Resultado da verificação is_shared: {is_shared}")

        if not is_folder and not has_access_to_file:
            typer.echo(f"Erro: '{server_filename}' não existe no servidor ou você não tem acesso")
            return
            
        # Caso seja uma pasta
        if is_folder:
            if not os.path.isdir(local_filepath):
                typer.echo(f"Erro: '{server_filename}' é uma pasta no servidor, mas '{local_filepath}' não é uma pasta local")
                return
                
            # Primeiro obter o metadata da pasta para saber quais arquivos existem atualmente
            metadata_resp = httpx.get(f"{API_URL}/read/{server_filename}/.metadata", headers=headers, verify=CA_CERT_PATH)
            
            if metadata_resp.status_code != 200:
                typer.echo(f"Erro ao obter metadata da pasta: {metadata_resp.status_code} - {metadata_resp.text}")
                return
                
            # Decifrar o metadata
            response_data = metadata_resp.json()
            encrypted_metadata = base64.b64decode(response_data["encrypted_file"])
            encrypted_key = base64.b64decode(response_data["encrypted_key"])
            
            private_key, _ = load_or_generate_rsa_keys(email)
            aes_key = decrypt_aes_key_with_rsa(encrypted_key, private_key)
            decrypted_metadata = decrypt_with_aes(encrypted_metadata, aes_key)
            old_metadata = json.loads(decrypted_metadata.decode())
            
            # Compor nova metadata baseada APENAS no conteúdo local
            new_metadata = {"type": "folder", "contents": {}}
            
            # Lista para acompanhar os arquivos que devem ser mantidos
            keep_files = []
            
            # Processar cada arquivo na pasta local
            files_updated = 0
            files_added = 0
            errors = 0
            
            typer.echo(f"Atualizando pasta '{server_filename}'...")
            
            # Carregar chaves RSA
            private_key, public_key = load_or_generate_rsa_keys(email)
            
            for root, dirs, files in os.walk(local_filepath):
                for file in files:
                    local_file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(local_file_path, local_filepath)
                    
                    # Normalizar separadores de caminho
                    rel_path = rel_path.replace("\\", "/")
                    keep_files.append(rel_path)
                    
                    # Adicionar ao novo metadata
                    new_metadata["contents"][rel_path] = {
                        "type": "file",
                        "size": os.path.getsize(local_file_path),
                        "mime": get_file_mime_type(local_file_path)
                    }
                    
                    server_file_path = f"{server_filename}/{rel_path}"
                    
                    # Verificar se o arquivo já existe no servidor
                    file_exists = rel_path in old_metadata.get("contents", {})
                        
                    if file_exists:
                        # Atualizar arquivo existente (mantendo a mesma chave)
                        try:
                            if is_shared:
                                success = update_file_shared(server_file_path, local_file_path, email, headers)
                            else:
                                success = update_file(server_file_path, local_file_path, email, headers)
                            if success:
                                files_updated += 1
                                typer.echo(f"  ✓ Atualizado: {rel_path}")
                            else:
                                errors += 1
                                typer.echo(f"  ✗ Falha ao atualizar: {rel_path}")
                        except Exception as e:
                            errors += 1
                            typer.echo(f"  ✗ Erro ao atualizar {rel_path}: {str(e)}")
                    else:
                        # Criar novo arquivo (Upload)
                        encrypted_data = encrypt_file(local_file_path, public_key)
                        
                        if not encrypted_data:
                            errors += 1
                            continue
                        
                        data = {
                            "filename": server_file_path,
                            "encrypted_file": encrypted_data["encrypted_file"],
                            "encrypted_key": encrypted_data["encrypted_key"]
                        }
                        
                        resp = httpx.post(f"{API_URL}/upload", json=data, headers=headers, verify=CA_CERT_PATH)
                        
                        if resp.status_code == 200:
                            files_added += 1
                            typer.echo(f"  + Adicionado: {rel_path}")
                        else:
                            errors += 1
                            typer.echo(f"  ✗ Falha ao adicionar {rel_path}: {resp.status_code} - {resp.text}")
            
            # Atualizar o arquivo de metadata
            metadata_str = json.dumps(new_metadata)
            
            # Criptografar com a chave AES original
            encrypted_metadata = encrypt_with_aes(metadata_str.encode(), aes_key)
            encrypted_metadata_b64 = base64.b64encode(encrypted_metadata).decode()
            encrypted_key_b64 = base64.b64encode(encrypted_key).decode()
            
            # Usar o novo endpoint write_folder para atualização completa da pasta
            folder_data = {
                "folder": server_filename,
                "keep_files": keep_files,
                "encrypted_metadata": encrypted_metadata_b64,
                "encrypted_key": encrypted_key_b64
            }
            
            resp = httpx.post(f"{API_URL}/write_folder", json=folder_data, headers=headers, verify=CA_CERT_PATH)
            
            shared_users = get_previous_shares(server_filename, email)
            if shared_users:
                typer.echo("\n🔁 Repartilhando a pasta atualizada com os utilizadores...")
                for target_email, perms in shared_users.items():
                    share_metadata(server_filename, email, target_email, perms)
                    
            if resp.status_code == 200:
                result = resp.json()
                files_removed = result.get("removed_files", 0)
                
                typer.echo(f"\nPasta '{server_filename}' atualizada com sucesso!")
                typer.echo(f"Arquivos atualizados: {files_updated}")
                typer.echo(f"Arquivos adicionados: {files_added}")
                typer.echo(f"Arquivos removidos: {files_removed}")
                if errors > 0:
                    typer.echo(f"Erros: {errors}")
            else:
                typer.echo(f"Erro ao atualizar pasta: {resp.status_code} - {resp.text}")
                
        else:
            # Arquivo simples
            if os.path.isdir(local_filepath):
                typer.echo(f"Erro: '{server_filename}' é um arquivo no servidor, mas '{local_filepath}' é uma pasta local")
                return
            if is_shared:
                success = update_file_shared(server_filename, local_filepath, email, headers)
            else:    
                success = update_file(server_filename, local_filepath, email, headers)
            if success:
                typer.echo(f"Arquivo '{server_filename}' atualizado com sucesso!")
            else:
                typer.echo(f"Erro ao atualizar '{server_filename}'")
    
    except Exception as e:
        typer.echo(f"Erro durante a atualização: {str(e)}")

def update_file(server_filename: str, local_filepath: str, email: str, headers: dict) -> bool:

    try:
        # Obter a chave criptografada do arquivo existente
        resp_key = httpx.get(f"{API_URL}/get_key/{server_filename}", headers=headers, verify=CA_CERT_PATH)
        
        if resp_key.status_code != 200:
            typer.echo(f"Erro ao obter a chave do arquivo {server_filename}: {resp_key.status_code} - {resp_key.text}")
            return False
        
        # Obter chave criptografada
        encrypted_key_b64 = resp_key.json()["encrypted_key"]
        encrypted_key = base64.b64decode(encrypted_key_b64)
        
        # Carregar chaves RSA do usuário
        private_key, _ = load_or_generate_rsa_keys(email)
        
        # Descriptografar a chave AES com a chave privada RSA
        aes_key = decrypt_aes_key_with_rsa(encrypted_key, private_key)
        
        # Ler conteúdo do arquivo local
        with open(local_filepath, "rb") as f:
            file_data = f.read()
        
        # Criptografar o novo conteúdo com a mesma chave AES
        encrypted_file = encrypt_with_aes(file_data, aes_key)
        
        # Codificar dados binários como base64 para transporte JSON
        encrypted_file_b64 = base64.b64encode(encrypted_file).decode()
        
        # Preparar o payload JSON
        data = {
            "filename": server_filename,
            "encrypted_file": encrypted_file_b64,
            "encrypted_key": encrypted_key_b64  # Mantendo a mesma chave
        }
        
        # Enviar a requisição para API
        resp = httpx.post(f"{API_URL}/write", json=data, headers=headers, verify=CA_CERT_PATH)
        
        if resp.status_code == 200:
            return True
        else:
            typer.echo(f"Erro ao atualizar {server_filename}: {resp.status_code} - {resp.text}")
            return False
    
    except Exception as e:
        typer.echo(f"Erro durante a atualização de {server_filename}: {str(e)}")
        return False    
    
def update_file_shared(server_filename: str, local_filepath: str, email: str, headers: dict) -> bool:

    try:
        # Obter a chave criptografada do arquivo existente
        resp_key = httpx.get(f"{API_URL}/get_key/{server_filename}", headers=headers, verify=CA_CERT_PATH)
        
        if resp_key.status_code != 200:
            typer.echo(f"Erro ao obter a chave do arquivo {server_filename}: {resp_key.status_code} - {resp_key.text}")
            return False
        
        # Obter a chave criptografada
        encrypted_key_b64 = resp_key.json()["encrypted_key"]
        encrypted_key = base64.b64decode(encrypted_key_b64)
        
        # Carregar as chaves RSA do usuário
        private_key, _ = load_or_generate_rsa_keys(email)
        
        # Descriptografar a chave AES com a chave privada RSA
        aes_key = decrypt_aes_key_with_rsa(encrypted_key, private_key)
        
        # Ler o conteúdo do arquivo local
        with open(local_filepath, "rb") as f:
            file_data = f.read()
        
        # Criptografar o novo conteúdo com a mesma chave AES
        encrypted_file = encrypt_with_aes(file_data, aes_key)
        
        # Codificar os dados binários como base64 para transporte JSON
        encrypted_file_b64 = base64.b64encode(encrypted_file).decode()
        
        # Preparar payload JSON
        data = {
            "filename": server_filename,
            "encrypted_file": encrypted_file_b64,
            "encrypted_key": encrypted_key_b64  # Mantendo a mesma chave
        }
        
        # Enviar requisição para API
        resp = httpx.post(f"{API_URL}/write_shared", json=data, headers=headers, verify=CA_CERT_PATH)
        
        if resp.status_code == 200:
            return True
        else:
            typer.echo(f"Erro ao atualizar {server_filename}: {resp.status_code} - {resp.text}")
            return False
    
    except Exception as e:
        typer.echo(f"Erro durante a atualização de {server_filename}: {str(e)}")
        return False

@app.command()
def read(filename: str, save_path: str = None):

    terminal_id = get_terminal_id()

    if not verify_active_session():
        return
    
    email = get_active_session(terminal_id)

    try:
        # Load auth token
        token = load_token(email)
        headers = {"Authorization": f"Bearer {token}"}
        
        # Load RSA keys
        private_key, _ = load_or_generate_rsa_keys(email)
        
        # First, get the list of files to verify what's available
        list_resp = httpx.get(f"{API_URL}/files", headers=headers, verify=CA_CERT_PATH)
        if list_resp.status_code != 200:
            typer.echo(f"Erro ao listar ficheiros: {list_resp.status_code}")
            return False
        
        file_list = list_resp.json()
        # Debugging output to see what files are available
        typer.echo("Arquivos disponíveis no servidor:")
        if "files" in file_list and file_list["files"]:
            for f in file_list["files"]:
                typer.echo(f"  - {f}")
        else:
            typer.echo("  (Nenhum arquivo encontrado)")
            
        if "folders" in file_list and file_list["folders"]:
            for f in file_list["folders"]:
                typer.echo(f"  - {f}/ (pasta)")
        else:
            typer.echo("  (Nenhuma pasta encontrada)")

        # Obter e listar ficheiros partilhados
        shared_folders = []
        shared_resp = httpx.get(f"{API_URL}/shared", headers=headers, verify=CA_CERT_PATH)
        if shared_resp.status_code == 200:
            shared_data = shared_resp.json()
            shared_folders = shared_data.get("folders", [])
            shared_files = shared_data.get("files", [])

            typer.echo("\nFicheiros partilhados consigo:")
            if shared_data["files"]:
                for f in shared_data["files"]:
                    typer.echo(f"  - {f}")
            else:
                typer.echo("  (Nenhum ficheiro partilhado)")

            if shared_data["folders"]:
                for f in shared_data["folders"]:
                    typer.echo(f"  - {f}/ (pasta partilhada)")
            else:
                typer.echo("  (Nenhuma pasta partilhada)")
        else:
            typer.echo(f"Erro ao obter lista de partilhas: {shared_resp.status_code} - {shared_resp.text}")

        is_folder = False        
        # Check if the requested filename is a folder
        if "folders" in file_list and filename in file_list["folders"]:
            is_folder = True
        elif filename in shared_folders:
            typer.echo(f"'{filename}' é uma pasta partilhada (identificada localmente).")
            is_folder = True
            
        if is_folder:
            # Try to get the metadata
            metadata_url = f"{API_URL}/read/{filename}/.metadata"
            typer.echo(f"A aceder a: {metadata_url}")
            metadata_resp = httpx.get(metadata_url, headers=headers, verify=CA_CERT_PATH)
            
            if metadata_resp.status_code != 200:
                typer.echo(f"Erro ao obter metadata da pasta: {metadata_resp.status_code} - {metadata_resp.text}")
                return False
                
            # Get encrypted metadata and key
            response_data = metadata_resp.json()
            encrypted_metadata = base64.b64decode(response_data["encrypted_file"])
            encrypted_key = base64.b64decode(response_data["encrypted_key"])
            
            # Decrypt the metadata
            aes_key = decrypt_aes_key_with_rsa(encrypted_key, private_key)
            decrypted_metadata = decrypt_with_aes(encrypted_metadata, aes_key)
            metadata = json.loads(decrypted_metadata.decode())
            
            # Create folder structure locally
            if save_path is None:
                user_path = set_user_path(email)
                save_path = os.path.join(user_path, filename)
            
            os.makedirs(save_path, exist_ok=True)
            
            # Process each file in the folder
            files_downloaded = 0
            errors = 0
            
            typer.echo(f"Baixando pasta '{filename}'...")
            
            # Download each file
            for file_path in metadata["contents"]:
                full_server_path = f"{filename}/{file_path}"
                local_file_path = os.path.join(save_path, file_path)
                
                # Ensure directory exists
                os.makedirs(os.path.dirname(local_file_path), exist_ok=True)
                
                try:
                    # Request file from server
                    file_resp = httpx.get(f"{API_URL}/read/{full_server_path}", headers=headers, verify=CA_CERT_PATH)
                    
                    if file_resp.status_code != 200:
                        typer.echo(f"Erro ao obter ficheiro {full_server_path}: {file_resp.status_code}")
                        errors += 1
                        continue
                    
                    # Decrypt and save file
                    response_data = file_resp.json()
                    encrypted_file = base64.b64decode(response_data["encrypted_file"])
                    encrypted_key = base64.b64decode(response_data["encrypted_key"])
                    
                    aes_key = decrypt_aes_key_with_rsa(encrypted_key, private_key)
                    decrypted_data = decrypt_with_aes(encrypted_file, aes_key)
                    
                    with open(local_file_path, "wb") as f:
                        f.write(decrypted_data)
                    
                    files_downloaded += 1
                    typer.echo(f"  ✓ {file_path}")
                
                except Exception as e:
                    typer.echo(f"  ✗ Erro em {file_path}: {str(e)}")
                    errors += 1
            
            typer.echo(f"\nPasta '{filename}' baixada com sucesso em '{save_path}'")
            typer.echo(f"Total de ficheiros: {files_downloaded + errors}")
            typer.echo(f"Baixados com sucesso: {files_downloaded}")
            if errors > 0:
                typer.echo(f"Erros: {errors}")
            
            return True
        else:
            # Regular file download
            resp = httpx.get(f"{API_URL}/read/{filename}", headers=headers, verify=CA_CERT_PATH)
            
            if resp.status_code != 200:
                if resp.status_code == 403:
                    typer.echo("✗ Sem permissões para ler este ficheiro.")
                elif resp.status_code == 404:
                    typer.echo("✗ Ficheiro não encontrado no servidor.")
                else:
                    typer.echo(f"Erro ao obter ficheiro: {resp.status_code} - {resp.text}")
                return False
            
            # Get encrypted file and key from response
            response_data = resp.json()
            encrypted_file = base64.b64decode(response_data["encrypted_file"])
            encrypted_key = base64.b64decode(response_data["encrypted_key"])
            
            # Decrypt the AES key using the private RSA key
            aes_key = decrypt_aes_key_with_rsa(encrypted_key, private_key)
            
            # Decrypt the file using the AES key
            decrypted_data = decrypt_with_aes(encrypted_file, aes_key)
            
            # Save the decrypted file
            if save_path is None:
                user_path = set_user_path(email)
                save_path = os.path.join(user_path, filename)
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            
            with open(save_path, "wb") as f:
                f.write(decrypted_data)
            
            typer.echo(f"Ficheiro '{filename}' baixado e decifrado com sucesso em '{save_path}'")
            return True
    
    except Exception as e:
        typer.echo(f"Erro durante a leitura: {str(e)}")
        return False   

@app.command()
def share(filename: str, to_email: str, permission: str = "READ"):

    terminal_id = get_terminal_id()

    if not verify_active_session():
        return
    
    from_email = get_active_session(terminal_id)

    try:
        token = load_token(from_email)
        headers = {"Authorization": f"Bearer {token}"}

        # Validar permissões
        if permission.upper() not in ["READ", "READ,WRITE", "APPEND", "READ,APPEND", "WRITE", "WRITE,APPEND", "READ,WRITE,APPEND"]:
            typer.echo("Permissão inválida. Use 'READ' ou 'READ,WRITE'")
            return
        permissions = permission.upper().split(",")

        # Verificar se o item é uma pasta ou um ficheiro
        list_resp = httpx.get(f"{API_URL}/files", headers=headers, verify=CA_CERT_PATH)
        if list_resp.status_code != 200:
            typer.echo(f"Erro ao listar ficheiros: {list_resp.status_code}")
            return
            
        file_list = list_resp.json()
        is_folder = False
        
        if "folders" in file_list and filename in file_list["folders"]:
            is_folder = True
            typer.echo(f"Partilhando pasta '{filename}'...")
        
        if is_folder:
            # Obter metadata da pasta
            metadata_resp = httpx.get(f"{API_URL}/read/{filename}/.metadata", headers=headers, verify=CA_CERT_PATH)
            
            if metadata_resp.status_code != 200:
                typer.echo(f"Erro ao obter metadata da pasta: {metadata_resp.status_code} - {metadata_resp.text}")
                return
                
            # Descriptografar os metadados
            response_data = metadata_resp.json()
            encrypted_metadata = base64.b64decode(response_data["encrypted_file"])
            encrypted_key = base64.b64decode(response_data["encrypted_key"])
            
            # Descriptografar metadata
            private_key, _ = load_or_generate_rsa_keys(from_email)
            aes_key = decrypt_aes_key_with_rsa(encrypted_key, private_key)
            decrypted_metadata = decrypt_with_aes(encrypted_metadata, aes_key)
            metadata = json.loads(decrypted_metadata.decode())
            
            # Partilhar o ficheiro de metadata
            share_file(f"{filename}/.metadata", from_email, to_email, permissions, headers)
            
            # Depois, partilhar cada ficheiro na pasta
            files_shared = 0
            errors = 0
            
            for file_path in metadata["contents"]:
                full_path = f"{filename}/{file_path}"
                try:
                    success = share_file(full_path, from_email, to_email, permissions, headers)
                    if success:
                        files_shared += 1
                        typer.echo(f"  ✓ {file_path}")
                    else:
                        errors += 1
                        typer.echo(f"  ✗ Erro ao partilhar {file_path}")
                except Exception as e:
                    errors += 1
                    typer.echo(f"  ✗ Erro ao partilhar {file_path}: {str(e)}")
            
            typer.echo(f"\nPasta '{filename}' partilhada com {to_email}")
            typer.echo(f"Total de ficheiros: {files_shared + errors}")
            typer.echo(f"Partilhados com sucesso: {files_shared}")
            if errors > 0:
                typer.echo(f"Erros: {errors}")
        
        else:
            # Partilhar um único ficheiro
            success = share_file(filename,from_email, to_email, permissions, headers)
            if success:
                typer.echo(f"Ficheiro '{filename}' partilhado com {to_email} com sucesso!")
            else:
                typer.echo(f"Erro ao partilhar ficheiro '{filename}'")

    except Exception as e:
        typer.echo(f"Erro durante partilha: {str(e)}")

def share_file(filename: str,from_email: str, to_email: str, permissions: list, headers: dict) -> bool:

    try:
        # Obter chave pública do destino + chave AES cifrada
        init_payload = {
            "filename": filename,
            "target_email": to_email
        }

        resp_init = httpx.post(f"{API_URL}/share/init", json=init_payload, headers=headers, verify=CA_CERT_PATH)
        if resp_init.status_code != 200:
            typer.echo(f"Erro ao iniciar partilha de {filename}: {resp_init.status_code} - {resp_init.text}")
            return False

        init_data = resp_init.json()
        encrypted_key_b64 = init_data["encrypted_key"]
        target_public_key_b64 = init_data["target_public_key"]

        # Decifrar chave AES do ficheiro
        encrypted_key = base64.b64decode(encrypted_key_b64)
        target_public_key_bytes = base64.b64decode(target_public_key_b64)

        private_key, _ = load_or_generate_rsa_keys(from_email)
        decrypted_aes_key = decrypt_aes_key_with_rsa(encrypted_key, private_key)

        # Re-encriptar com a chave pública do destinatário 
        target_public_key = serialization.load_pem_public_key(target_public_key_bytes)
        encrypted_key_for_target = encrypt_aes_key_with_rsa(decrypted_aes_key, target_public_key)
        encrypted_key_for_target_b64 = base64.b64encode(encrypted_key_for_target).decode()

        #Enviar chave re-encriptada + permissões
        complete_payload = {
            "filename": filename,
            "target_email": to_email,
            "encrypted_key_for_target": encrypted_key_for_target_b64,
            "permissions": permissions
        }

        resp_complete = httpx.post(f"{API_URL}/share/complete", json=complete_payload, headers=headers, verify=CA_CERT_PATH)
        if resp_complete.status_code == 200:
            return True
        else:
            typer.echo(f"Erro ao concluir partilha de {filename}: {resp_complete.status_code} - {resp_complete.text}")
            return False

    except Exception as e:
        typer.echo(f"Erro durante partilha de {filename}: {str(e)}")
        return False
    
@app.command()
def append(server_filename: str, local_filepath: str):
    
    terminal_id = get_terminal_id()
    if not verify_active_session():
        return
    email = get_active_session(terminal_id)

    # Verificar se o arquivo local existe
    if not os.path.exists(local_filepath):
        typer.echo(f"Erro: Caminho local '{local_filepath}' não encontrado")
        return
    
    # Verificar se o caminho local é um diretório
    if os.path.isdir(local_filepath):
        typer.echo(f"O caminho '{local_filepath}' é um diretório. Processando como append para pasta...")
        append_folder(server_filename, local_filepath, email)
        return
    
    try:
        # Carregar o token de autenticação
        token = load_token(email)
        headers = {"Authorization": f"Bearer {token}"}
        
        # Verificar se o arquivo existe no servidor
        resp_list = httpx.get(f"{API_URL}/files", headers=headers, verify=CA_CERT_PATH)
        
        if resp_list.status_code != 200:
            typer.echo(f"Erro ao listar arquivos: {resp_list.status_code}")
            return
        
        file_list = resp_list.json()
        
        # Verificar se o arquivo existe
        if "folders" in file_list and server_filename in file_list["folders"]:
            typer.echo(f"'{server_filename}' é uma pasta no servidor. Processando como append para pasta...")
            append_folder(server_filename, local_filepath, email)
            return
        
        if "files" not in file_list or server_filename not in file_list["files"]:
            typer.echo(f"Erro: '{server_filename}' não existe no servidor ou você não tem acesso")
            return
        
        # Primeiro, baixar o arquivo original para obter o seu conteúdo
        resp_read = httpx.get(f"{API_URL}/read/{server_filename}", headers=headers, verify=CA_CERT_PATH)
        if resp_read.status_code != 200:
            typer.echo(f"Erro ao ler o arquivo original {server_filename}: {resp_read.status_code} - {resp_read.text}")
            return
            
        read_data = resp_read.json()
        encrypted_content = base64.b64decode(read_data["encrypted_file"])
        encrypted_key = base64.b64decode(read_data["encrypted_key"])
        
        # Carregar chaves RSA do usuário
        private_key, _ = load_or_generate_rsa_keys(email)
        
        # Descriptografar a chave AES com a chave privada RSA
        aes_key = decrypt_aes_key_with_rsa(encrypted_key, private_key)
        
        # Descriptografar o conteúdo original
        original_content = decrypt_with_aes(encrypted_content, aes_key)
        
        # Ler o conteúdo do arquivo local a ser adicionado
        with open(local_filepath, "rb") as f:
            content_to_append = f.read()
        
        # Combinar os conteúdos
        combined_content = original_content + content_to_append
        
        # Criptografar o conteúdo combinado com a mesma chave AES
        encrypted_combined_content = encrypt_with_aes(combined_content, aes_key)
        
        # Codificar dados binários como base64 para transporte JSON
        encrypted_file_b64 = base64.b64encode(encrypted_combined_content).decode()
        encrypted_key_b64 = base64.b64encode(encrypted_key).decode()
        
        # Preparar payload JSON para o endpoint de write
        data = {
            "filename": server_filename,
            "encrypted_file": encrypted_file_b64,
            "encrypted_key": encrypted_key_b64
        }
        
        # Enviar requisição para o endpoint de write
        resp = httpx.post(f"{API_URL}/write", json=data, headers=headers, verify=CA_CERT_PATH)
        
        if resp.status_code == 200:
            typer.echo(f"Conteúdo adicionado com sucesso ao arquivo '{server_filename}'!")
            typer.echo(f"Tamanho original: {len(original_content)} bytes")
            typer.echo(f"Conteúdo adicionado: {len(content_to_append)} bytes")
            typer.echo(f"Novo tamanho total: {len(combined_content)} bytes")
        else:
            typer.echo(f"Erro ao adicionar conteúdo a {server_filename}: {resp.status_code} - {resp.text}")
    
    except Exception as e:
        typer.echo(f"Erro durante a operação de append: {str(e)}")

def append_folder(folder_name: str, local_path: str, email: str):

    if not os.path.exists(local_path):
        typer.echo(f"Erro: Caminho local '{local_path}' não encontrado")
        return

    try:
        token = load_token(email)
        headers = {"Authorization": f"Bearer {token}"}

        metadata_resp = httpx.get(f"{API_URL}/read/{folder_name}/.metadata", headers=headers, verify=CA_CERT_PATH)
        if metadata_resp.status_code != 200:
            typer.echo(f"Erro ao obter metadata da pasta: {metadata_resp.status_code} - {metadata_resp.text}")
            return

        response_data = metadata_resp.json()
        encrypted_metadata = base64.b64decode(response_data["encrypted_file"])
        encrypted_key = base64.b64decode(response_data["encrypted_key"])

        private_key, public_key = load_or_generate_rsa_keys(email)
        aes_key = decrypt_aes_key_with_rsa(encrypted_key, private_key)
        decrypted_metadata = decrypt_with_aes(encrypted_metadata, aes_key)
        metadata = json.loads(decrypted_metadata.decode())

        existing_files = set(metadata.get("contents", {}).keys())

        new_files_added = 0
        errors = 0

        source_folder_name = os.path.basename(local_path)
 
        is_dir_to_dir = os.path.isdir(local_path)
        
        typer.echo(f"Adicionando novos arquivos à pasta '{folder_name}'...")

        keep_files = list(existing_files)

        for root, dirs, files in os.walk(local_path):
            for file in files:
                local_file_path = os.path.join(root, file)
                
                rel_path = os.path.relpath(local_file_path, os.path.dirname(local_path) if is_dir_to_dir else local_path).replace("\\", "/")
                
                if is_dir_to_dir and not rel_path.startswith(source_folder_name):
                    rel_path = f"{source_folder_name}/{rel_path}"
                
                server_file_path = f"{folder_name}/{rel_path}"

                if rel_path in existing_files:
                    typer.echo(f"  ~ Ignorado (já existe): {rel_path}")
                    continue

                with open(local_file_path, "rb") as f:
                    plaintext = f.read()
                encrypted_file = encrypt_with_aes(plaintext, aes_key)
                encrypted_file_b64 = base64.b64encode(encrypted_file).decode()
                encrypted_key_b64 = base64.b64encode(encrypted_key).decode()

                data = {
                    "filename": server_file_path,
                    "encrypted_file": encrypted_file_b64,
                    "encrypted_key": encrypted_key_b64
                }

                resp = httpx.post(f"{API_URL}/upload", json=data, headers=headers, verify=CA_CERT_PATH)
                if resp.status_code == 200:
                    typer.echo(f"  + Adicionado: {rel_path}")
                    metadata["contents"][rel_path] = {
                        "type": "file",
                        "size": os.path.getsize(local_file_path),
                        "mime": get_file_mime_type(local_file_path)
                    }
                    keep_files.append(rel_path)
                    new_files_added += 1
                else:
                    typer.echo(f"  ✗ Falha ao adicionar {rel_path}: {resp.status_code} - {resp.text}")
                    errors += 1

        # Atualizar metadata
        metadata_str = json.dumps(metadata)
        encrypted_metadata = encrypt_with_aes(metadata_str.encode(), aes_key)
        encrypted_metadata_b64 = base64.b64encode(encrypted_metadata).decode()

        folder_data = {
            "folder": folder_name,
            "keep_files": keep_files,
            "encrypted_metadata": encrypted_metadata_b64,
            "encrypted_key": base64.b64encode(encrypted_key).decode()
        }

        resp = httpx.post(f"{API_URL}/write_folder", json=folder_data, headers=headers, verify=CA_CERT_PATH)
        if resp.status_code == 200:
            typer.echo(f"\nPasta '{folder_name}' atualizada com {new_files_added} novos arquivos.")
            if errors > 0:
                typer.echo(f"Erros: {errors}")
        else:
            typer.echo(f"Erro ao atualizar metadata da pasta: {resp.status_code} - {resp.text}")

    except Exception as e:
        typer.echo(f"Erro durante a operação de append_folder: {str(e)}")
    
if __name__ == "__main__":
    app()