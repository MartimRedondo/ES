from ImportPaths import *
from msg import *
from aux import *

@app.post("/register", response_model=dict)
def register_user(data: RegisterData):
    if data.email in USERS_DB:
        raise HTTPException(status_code=400, detail="Email já registado.")
    
    user_id = str(uuid.uuid4())
    password_decifrada = server.decrypt_password(data.password)

    pass_hash = ph.hash(password_decifrada)

    USERS_DB[data.email] = {
        "name": data.name,
        "password": pass_hash
    }
    USER_IDS[data.email] = user_id

    user_path = os.path.join("DB", data.email, "keys")
    os.makedirs(user_path, exist_ok=True)

    public_key_pem = base64.b64decode(data.public_key)
    with open(os.path.join(user_path, "public_key.pem"), "wb") as f:
        f.write(public_key_pem)

    return {"message": "Registo feito com sucesso"}

@app.post("/nonce", response_model=dict)
def nonce(data: User):
    
    nonce = os.urandom(16).hex()
    #print (f"Nonce gerado: {nonce}")
    NONCES[data.email] = {
        "nonce": nonce,
        "timestamp": time.time()
    }
    #print (f"Nonce guardado: {NONCES}")
    
    return {"email": data.email, "nonce": nonce}

@app.post("/login", response_model=TokenResponse)
def login(data: LoginData):
    email = data.username
    credenciais = data.password
    
    try:
        parts = credenciais.split(':', 1)

        if len(parts) != 2:
            raise HTTPException(status_code=400, detail="Formato de credenciais inválido")
        
        nonce, password_cifrada = parts

    except Exception:
        raise HTTPException(status_code=400, detail="Formato de credenciais inválido")
    
    nonce_data = NONCES.get(email)
    if not nonce_data:
        raise HTTPException(status_code=400, detail="Nonce não solicitado. Solicite um nonce primeiro.")
    
    if nonce_data["nonce"] != nonce:
        raise HTTPException(status_code=400, detail="Nonce inválido")
    
    if time.time() - nonce_data["timestamp"] > NONCE_EXPIRY_SECONDS:
        NONCES.pop(email, None)
        raise HTTPException(status_code=400, detail="Nonce expirado. Solicite um novo nonce.")
    
    NONCES.pop(email, None)
    
    user = USERS_DB.get(email)
    if not user:
        raise HTTPException(status_code=400, detail="Email não registado")

    try:
        ph.verify(user["password"], server.decrypt_password(password_cifrada))
    except Exception:
        raise HTTPException(status_code=400, detail="Password inválida")
    
    print (SRV.Fore.GREEN + "Password, Nonce e e Email verificados com sucesso")

    token = create_access_token(data={"sub": email})
    return TokenResponse(access_token=token)

@app.get("/files", response_model=ListFilesResponse)
def list_files(current_user: str = Depends(get_current_user)):
    user_dir = os.path.join("DB", current_user)
    files_path = os.path.join(user_dir, "OWNER", "FILES")
    os.makedirs(files_path, exist_ok=True)
    
    # Listas para armazenar arquivos e pastas
    files = []
    folders = []
    
    # Primeiro, listar diretórios diretamente
    for item in os.listdir(files_path):
        item_path = os.path.join(files_path, item)
        if os.path.isdir(item_path):
            # É um diretório real
            folders.append(item)
    
    # Depois, listar arquivos no diretório principal
    for item in os.listdir(files_path):
        item_path = os.path.join(files_path, item)
        if os.path.isfile(item_path) and item.endswith(".encrypted") and not item.startswith(".metadata"):
            filename = item[:-10]  # Remover ".encrypted"
            if "/" not in filename and "\\" not in filename:  # Garantir que não é um arquivo dentro de uma pasta
                files.append(filename)
    
    return ListFilesResponse(files=files, folders=folders)

@app.get("/shared", response_model=ListFilesResponse)
def list_shared_files(current_user: str = Depends(get_current_user)):

    shared_base = os.path.join("DB", current_user, "SHARED_WITH")
    files = []
    folders = []

    if not os.path.exists(shared_base):
        return ListFilesResponse(files=[], folders=[])

    for owner in os.listdir(shared_base):
        owner_path = os.path.join(shared_base, owner)
        for root, _, filenames in os.walk(owner_path):
            for fname in filenames:
                # Remover .encrypted se for ficheiro
                full_path = os.path.relpath(os.path.join(root, fname), owner_path)
                if fname.endswith(".encrypted") and not fname.startswith(".metadata"):
                    logical_name = full_path[:-10]
                    files.append(logical_name.replace("\\", "/"))
                elif fname == ".metadata":
                    folder_name = os.path.relpath(root, owner_path)
                    folders.append(folder_name.replace("\\", "/"))
    
    return ListFilesResponse(files=files, folders=folders)

@app.get("/shared_write", response_model=ListFilesResponse)
def list_shared_files(current_user: str = Depends(get_current_user)):

    shared_base = os.path.join("DB", current_user, "SHARED_WITH")
    files = []
    folders = []

    if not os.path.exists(shared_base):
        return ListFilesResponse(files=[], folders=[])

    for owner in os.listdir(shared_base):
        owner_path = os.path.join(shared_base, owner)
        for root, _, filenames in os.walk(owner_path):
            for fname in filenames:
                # Caminho relativo ao dono
                full_path = os.path.relpath(os.path.join(root, fname), owner_path)
                logical_name = full_path.replace("\\", "/")

                if fname.endswith(".key.encrypted") or fname == ".metadata.key.encrypted":
                    continue  # Ignorar chaves
                elif fname == ".metadata":
                    folder_name = os.path.relpath(root, owner_path).replace("\\", "/")
                    folders.append(folder_name)
                else:
                    files.append(logical_name)

    return ListFilesResponse(files=files, folders=folders)

@app.post("/upload", response_model=dict)
def upload_file(data: UploadData, current_user: str = Depends(get_current_user)):

    files_dir = os.path.join("DB", current_user, "OWNER", "FILES")
    keys_dir = os.path.join("DB", current_user, "OWNER", "KEYS")
    os.makedirs(files_dir, exist_ok=True)
    os.makedirs(keys_dir, exist_ok=True)

    # Verificar se é um arquivo dentro de uma pasta
    if "/" in data.filename:
        # Criar os subdiretórios necessários
        folder_parts = os.path.dirname(data.filename).split("/")
        current_path = files_dir
        for part in folder_parts:
            current_path = os.path.join(current_path, part)
            os.makedirs(current_path, exist_ok=True)
        
        # Mesmo para os diretórios de chaves
        current_path = keys_dir
        for part in folder_parts:
            current_path = os.path.join(current_path, part)
            os.makedirs(current_path, exist_ok=True)

    # Caminhos
    encrypted_file_path = os.path.join(files_dir, data.filename + ".encrypted")
    encrypted_key_path = os.path.join(keys_dir, data.filename + ".key.encrypted")

    # Garantir que os diretórios existem
    os.makedirs(os.path.dirname(encrypted_file_path), exist_ok=True)
    os.makedirs(os.path.dirname(encrypted_key_path), exist_ok=True)

    try:
        # Guardar ficheiro cifrado
        with open(encrypted_file_path, "wb") as f:
            f.write(base64.b64decode(data.encrypted_file))

        # Guardar chave cifrada
        with open(encrypted_key_path, "wb") as f:
            f.write(base64.b64decode(data.encrypted_key))

        return {"message": f"Ficheiro '{data.filename}' enviado com sucesso."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao guardar ficheiro: {e}")


@app.get("/get_key/{filename}", response_model=dict)
def get_key(filename: str, current_user: str = Depends(get_current_user)):

    # Diretórios como owner
    keys_dir = os.path.join("DB", current_user, "OWNER", "KEYS")
    encrypted_key_path = os.path.join(keys_dir, filename + ".key.encrypted")

    if os.path.exists(encrypted_key_path):
        try:
            with open(encrypted_key_path, "rb") as f:
                encrypted_key = base64.b64encode(f.read()).decode()
            return {"encrypted_key": encrypted_key}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Erro ao ler chave: {e}")

    # Procurar como ficheiro partilhado
    shared_base = os.path.join("DB", current_user, "SHARED_WITH")
    if not os.path.exists(shared_base):
        raise HTTPException(status_code=403, detail="Sem permissões ou chave não encontrada.")

    for owner in os.listdir(shared_base):
        shared_key_path = os.path.join(shared_base, owner, filename + ".key.encrypted")

        if os.path.exists(shared_key_path):
            # Verificar permissões
            permissions = server.get_permissions(owner)
            user_perms = permissions.get(filename, {}).get(current_user, [])

            if "WRITE" not in user_perms and "READ,WRITE" not in user_perms:
                raise HTTPException(status_code=403, detail="Sem permissões de escrita para este ficheiro.")

            try:
                with open(shared_key_path, "rb") as f:
                    encrypted_key = base64.b64encode(f.read()).decode()
                return {"encrypted_key": encrypted_key}
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Erro ao ler chave partilhada: {e}")

    raise HTTPException(status_code=404, detail=f"Chave para o ficheiro '{filename}' não encontrada.")

@app.post("/write_shared", response_model=dict)
def write_file(data: WriteData, current_user: str = Depends(get_current_user)):

    shared_base = os.path.join("DB", current_user, "SHARED_WITH")
    found = False
    encrypted_file_path = ""
    #encrypted_key_path = ""
    #owner_email = None

    # Procurar entre todos os owners
    for owner in os.listdir(shared_base):
        test_file_path = os.path.join(shared_base, owner, data.filename)
        test_key_path = test_file_path + ".key.encrypted"

        if os.path.exists(test_file_path):
            encrypted_file_path = test_file_path
            #encrypted_key_path = test_key_path
            #owner_email = owner
            found = True
            break

    if not found:
        raise HTTPException(status_code=404, detail=f"Ficheiro '{data.filename}' não encontrado em partilhas.")

    #print(f"[DEBUG] Ficheiro encontrado. Owner = {owner_email}")
    #print(f"[DEBUG] Path ficheiro: {encrypted_file_path}")
    #print(f"[DEBUG] Path chave: {encrypted_key_path}")

    try:
        with open(encrypted_file_path, "wb") as f:
            f.write(base64.b64decode(data.encrypted_file))

        return {"message": f"Ficheiro '{data.filename}' atualizado com sucesso."}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao atualizar ficheiro: {e}")
    

@app.post("/write", response_model=dict)
def write_file(data: WriteData, current_user: str = Depends(get_current_user)):

    # Diretórios
    files_dir = os.path.join("DB", current_user, "OWNER", "FILES")
    keys_dir = os.path.join("DB", current_user, "OWNER", "KEYS")
    
    # Caminhos
    encrypted_file_path = os.path.join(files_dir, data.filename + ".encrypted")
    encrypted_key_path = os.path.join(keys_dir, data.filename + ".key.encrypted")

    #print(f"[DEBUG] encrypted_file_path '{encrypted_file_path}'")
    #print(f"[DEBUG] encrypted_key_path '{encrypted_key_path}'")
    
    # Verificar se o ficheiro existe
    if not os.path.exists(encrypted_file_path):
        raise HTTPException(status_code=404, detail=f"Ficheiro '{data.filename}' não encontrado.")
    
    try:
        # Guardar ficheiro cifrado
        with open(encrypted_file_path, "wb") as f:
            f.write(base64.b64decode(data.encrypted_file))

        with open(encrypted_key_path, "wb") as f:
            f.write(base64.b64decode(data.encrypted_key))
   
        # Obter utilizadores com quem o ficheiro foi partilhado
        permissions = server.get_permissions(current_user)
        #print(f"[DEBUG] A verificar permissões partilhadas para '{data.filename}'")

        if data.filename in permissions:
            shared_users = permissions[data.filename]
            #print(f"[DEBUG] Ficheiro '{data.filename}' partilhado com: {list(shared_users.keys())}")
            
            for target_user, perms in shared_users.items():
                #print(f"[DEBUG] A processar utilizador '{target_user}' com permissões: {perms}")
                if "READ" in perms or "WRITE" in perms or "READ,WRITE" in perms:
                    shared_dir = os.path.join("DB", target_user, "SHARED_WITH", current_user)
                    os.makedirs(shared_dir, exist_ok=True)

                    shared_file_path = os.path.join(shared_dir, data.filename)

                    #print(f"[DEBUG] -> Path do ficheiro: {shared_file_path}")

                    try:
                        # Atualizar ficheiro cifrado
                        with open(shared_file_path, "wb") as f:
                            f.write(base64.b64decode(data.encrypted_file))

                        print(f"[DEBUG] ✓ Atualização feita com sucesso para {target_user}")      
                    except Exception as e:
                        print(f"[!] Falha ao atualizar versão partilhada com {target_user}: {e}")

        return {"message": f"Ficheiro '{data.filename}' atualizado com sucesso."}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao atualizar ficheiro: {e}")
    
    
@app.delete("/delete/{filename:path}", response_model=dict)
def delete_file(
    filename: str = Path(..., description="Caminho relativo do arquivo a ser excluído"),
    current_user: str = Depends(get_current_user)
):

    # Normalizar e proteger os caminhos
    safe_filename = os.path.normpath(filename)
    if safe_filename.startswith("..") or os.path.isabs(safe_filename):
        raise HTTPException(status_code=400, detail="Nome de arquivo inválido.")
    
    # Verificar se o usuário é o proprietário do arquivo
    files_dir = os.path.join("DB", current_user, "OWNER", "FILES")
    keys_dir = os.path.join("DB", current_user, "OWNER", "KEYS")
    
    file_path = os.path.join(files_dir, safe_filename + ".encrypted")
    key_path = os.path.join(keys_dir, safe_filename + ".key.encrypted")
    
    # Verificar se o arquivo existe
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail=f"Arquivo '{filename}' não encontrado.")
    
    try:
        # Excluir o arquivo e sua chave
        if os.path.exists(file_path):
            os.remove(file_path)
        
        if os.path.exists(key_path):
            os.remove(key_path)
        
        return {"message": f"Arquivo '{filename}' excluído com sucesso."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao excluir arquivo: {e}")

@app.post("/write_folder", response_model=dict)
def write_folder(
    data: dict, 
    current_user: str = Depends(get_current_user)
):
    folder_name = data.get("folder")
    if not folder_name:
        raise HTTPException(status_code=400, detail="Nome da pasta não especificado.")
    
    keep_files = data.get("keep_files", [])
    encrypted_metadata = data.get("encrypted_metadata")
    encrypted_key = data.get("encrypted_key")
    
    if not encrypted_metadata or not encrypted_key:
        raise HTTPException(status_code=400, detail="Metadata da pasta não fornecido.")
    
    # Diretórios
    files_dir = os.path.join("DB", current_user, "OWNER", "FILES", folder_name)
    keys_dir = os.path.join("DB", current_user, "OWNER", "KEYS", folder_name)
    
    # Verificar se a pasta existe
    if not os.path.isdir(files_dir):
        raise HTTPException(status_code=404, detail=f"Pasta '{folder_name}' não encontrada.")
    
    try:
        # Atualizar o arquivo de metadata
        metadata_file_path = os.path.join(files_dir, ".metadata.encrypted")
        metadata_key_path = os.path.join(keys_dir, ".metadata.key.encrypted")
        
        with open(metadata_file_path, "wb") as f:
            f.write(base64.b64decode(encrypted_metadata))
        
        with open(metadata_key_path, "wb") as f:
            f.write(base64.b64decode(encrypted_key))
        
        # Listar todos os arquivos atuais na pasta
        existing_files = []
        for root, _, files in os.walk(files_dir):
            for file in files:
                if file != ".metadata.encrypted" and file.endswith(".encrypted"):
                    rel_path = os.path.relpath(os.path.join(root, file), files_dir)
                    file_name = rel_path[:-10]  # Remover ".encrypted"
                    existing_files.append(file_name)
        
        # Identificar arquivos para remover
        files_to_remove = [f for f in existing_files if f not in keep_files]
        
        # Remover arquivos
        removed_count = 0
        for file in files_to_remove:
            file_path = os.path.join(files_dir, file + ".encrypted")
            key_path = os.path.join(keys_dir, file + ".key.encrypted")
            
            if os.path.exists(file_path):
                os.remove(file_path)
                removed_count += 1
            
            if os.path.exists(key_path):
                os.remove(key_path)

        # Propagar alterações da metadata para utilizadores com permissões
        permissions = server.get_permissions(current_user)
        metadata_key_logical = f"{folder_name}/.metadata"

        #print(f"[DEBUG] A verificar partilhas para: '{metadata_key_logical}'")
        if metadata_key_logical in permissions:
            shared_users = permissions[metadata_key_logical]
            #print(f"[DEBUG] Pasta '{folder_name}' partilhada com: {list(shared_users.keys())}")

            for target_user, perms in shared_users.items():
                #print(f"[DEBUG] Processando utilizador: {target_user} com permissões {perms}")
                if "READ" in perms or "WRITE" in perms or "READ,WRITE" in perms or "READ,APPEND" in perms or "WRITE" in perms or "WRITE,APPEND"in perms or "READ,WRITE,APPEND" in perms:
                    shared_folder_path = os.path.join("DB", target_user, "SHARED_WITH", current_user, folder_name)
                    if os.path.exists(shared_folder_path):
                        shutil.rmtree(shared_folder_path)
                        print(f"[DEBUG] Apagada versão antiga partilhada com {target_user}")
                else:
                    print(f"[DEBUG] Ignorado utilizador {target_user} por não ter permissões de leitura ou escrita")
        else:
            print(f"[DEBUG] Pasta '{folder_name}' não partilhada ou sem permissões de escrita.")

        return {
            "message": f"Pasta '{folder_name}' atualizada com sucesso.",
            "removed_files": removed_count
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao atualizar pasta: {e}")

@app.get("/read/{filename:path}", response_model=ReadFileResponse)
def read_file(
    filename: str = Path(..., description="Caminho relativo dentro de FILES"),
    current_user: str = Depends(get_current_user)
):

    safe_filename = os.path.normpath(filename)
    # print(f"Nome de arquivo normalizado: {safe_filename}")
    
    if safe_filename.startswith("..") or os.path.isabs(safe_filename):
        raise HTTPException(status_code=400, detail="Nome de ficheiro inválido.")

    # Verifica se o utilizador é o OWNER
    file_path = os.path.join("DB", current_user, "OWNER", "FILES", safe_filename + ".encrypted")
    key_path = os.path.join("DB", current_user, "OWNER", "KEYS", safe_filename + ".key.encrypted")
    
    # print(f"Verificando se é owner em: {file_path}")
    
    if os.path.exists(file_path) and os.path.exists(key_path):
        # print("✓ É o owner do arquivo")
        # É o owner
        try:
            with open(file_path, "rb") as f:
                encrypted_file = base64.b64encode(f.read()).decode()
            with open(key_path, "rb") as f:
                encrypted_key = base64.b64encode(f.read()).decode()
            return ReadFileResponse(encrypted_file=encrypted_file, encrypted_key=encrypted_key)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Erro ao ler ficheiro: {e}")

    # Caso contrário, verificar se é utilizador partilhado
    shared_base = os.path.join("DB", current_user, "SHARED_WITH")
    # print(f"Verificando compartilhamentos em: {shared_base}")
    
    if not os.path.exists(shared_base):
        print("✗ Diretório de compartilhamentos não encontrado")
        raise HTTPException(status_code=403, detail="Sem permissões para aceder a este ficheiro.")

    # print(f"Diretórios de compartilhamento: {os.listdir(shared_base)}")
    
    # Verificar se é um arquivo .metadata
    is_metadata = safe_filename.endswith(".metadata")
    # print(f"É um arquivo de metadata? {is_metadata}")
    
    if is_metadata:
        folder_path = safe_filename[:-9]  # Remove apenas "/.metadata"
        # print(f"Caminho da pasta: {folder_path}")
        
        # Procurar em todos os donos de compartilhamentos
        for owner in os.listdir(shared_base):
            # print(f"\nVerificando compartilhamentos do proprietário: {owner}")
            
            # Localizar o arquivo .metadata físico
            metadata_path = os.path.join(shared_base, owner, folder_path, ".metadata")
            metadata_key_path = os.path.join(shared_base, owner, folder_path, ".metadata.key.encrypted")
            
            # print(f"Procurando metadata em: {metadata_path}")
            # print(f"Procurando chave em: {metadata_key_path}")
            
            metadata_exists = os.path.exists(metadata_path)
            key_exists = os.path.exists(metadata_key_path)
            
            # print(f"Arquivo metadata existe? {metadata_exists}")
            # print(f"Arquivo de chave existe? {key_exists}")
            
            if metadata_exists and key_exists:
                # print("✓ Arquivos físicos encontrados")
                
                # Obter permissões do proprietário
                permissions = server.get_permissions(owner)
                # print(f"Permissões disponíveis do proprietário:")
                for perm_key in permissions.keys():
                    if current_user in permissions[perm_key]:
                        print(f"  - '{perm_key}': {permissions[perm_key][current_user]}")
                
                # Verificar permissão exata para o metadata
                folder_path2 = folder_path[:-1]  # Remove apenas "\"
                exact_metadata_path = f"{folder_path2}/.metadata"
                # print(f"Procurando permissões para: '{exact_metadata_path}'")
                
                if exact_metadata_path in permissions:
                    # print(f"✓ Caminho encontrado nas permissões!")
                    user_perms = permissions[exact_metadata_path].get(current_user)
                    # print(f"Permissões para o usuário: {user_perms}")
                else:
                    #print(f"✗ Caminho não encontrado nas permissões")
                    pass
                    
                file_perms = permissions.get(exact_metadata_path, {}).get(current_user)
                # print(f"Permissões recuperadas: {file_perms}")
                
                if not file_perms or "READ" not in file_perms:
                    # print(f"✗ Permissões de leitura não encontradas: {file_perms}")
                    raise HTTPException(status_code=403, detail=f"Não tem permissões de leitura para o metadata. -> {file_perms}")
                
                # print("✓ Lendo arquivos para retornar")
                try:
                    with open(metadata_path, "rb") as f:
                        encrypted_file = base64.b64encode(f.read()).decode()
                    with open(metadata_key_path, "rb") as f:
                        encrypted_key = base64.b64encode(f.read()).decode()
                    # print("✓ Leitura bem-sucedida, retornando arquivos")
                    return ReadFileResponse(encrypted_file=encrypted_file, encrypted_key=encrypted_key)
                except Exception as e:
                    # print(f"✗ Erro ao ler arquivos: {e}")
                    raise HTTPException(status_code=500, detail=f"Erro ao ler metadata: {e}")
            else:
                # print(f"✗ Arquivos físicos não encontrados neste proprietário")
                pass
        
        # print("✗ Metadata não encontrado em nenhum proprietário")
        raise HTTPException(status_code=404, detail="Metadata não encontrado")

    for owner in os.listdir(shared_base):
        shared_folder = os.path.join(shared_base, owner)
        # print(f"Verificando em pasta compartilhada: {shared_folder}")

        # Tentar localizar ficheiros partilhados com e sem extensão .encrypted
        logical_name = safe_filename
        if logical_name.endswith(".encrypted"):
            logical_name = logical_name.removesuffix(".encrypted")
        
        # print(f"Nome lógico do arquivo: {logical_name}")

        possible_paths = [
            (
                os.path.join(shared_folder, logical_name + ".encrypted"),
                os.path.join(shared_folder, logical_name + ".key.encrypted")
            ),
            (
                os.path.join(shared_folder, logical_name),
                os.path.join(shared_folder, logical_name + ".key.encrypted")
            ),
            (
                os.path.join(shared_folder, logical_name.replace("\\", "/") + ".encrypted"),
                os.path.join(shared_folder, logical_name.replace("\\", "/") + ".key.encrypted")
            ),
            (
                os.path.join(shared_folder, logical_name.replace("\\", "/")),
                os.path.join(shared_folder, logical_name.replace("\\", "/") + ".key.encrypted")
            )
        ]
                
        for shared_file_path, shared_key_path in possible_paths:
            # print(f"Verificando arquivo em: {shared_file_path}")
            # print(f"Verificando chave em: {shared_key_path}")
            
            if os.path.exists(shared_file_path) and os.path.exists(shared_key_path):
                # print("✓ Arquivo e chave encontrados")
                
                # Verificar permissões
                permissions = server.get_permissions(owner)
                # print(f"Verificando permissões para: '{logical_name}'")
                
                file_perms = permissions.get(logical_name, {}).get(current_user)
                # print(f"Permissões encontradas: {file_perms}")
                
                # Tentar diretamente
                if not file_perms:
                    alt_safe_filename = safe_filename.replace("\\", "/")
                    # print(f"Tentativa alternativa com: '{alt_safe_filename}'")
                    owner_perms = permissions.get(alt_safe_filename)
                    if owner_perms:
                        file_perms = owner_perms.get(current_user)
                        # print(f"Permissões alternativas encontradas: {file_perms}")
                
                # Tentar com nome alternativo (.encrypted removido)
                if not file_perms and safe_filename.endswith(".encrypted"):
                    alt_name = safe_filename.removesuffix(".encrypted")
                    # print(f"Tentativa com nome sem .encrypted: '{alt_name}'")
                    alt_perms = permissions.get(alt_name)
                    if alt_perms:
                        file_perms = alt_perms.get(current_user)
                        # print(f"Permissões encontradas com nome alternativo: {file_perms}")
                
                if not file_perms or "READ" not in file_perms:
                    # print(f"✗ Sem permissões de leitura: {file_perms}")
                    raise HTTPException(status_code=403, detail=f"Não tem permissões de leitura. -> {file_perms}")

                # print("✓ Permissões de leitura encontradas, retornando arquivo")
                try:
                    with open(shared_file_path, "rb") as f:
                        encrypted_file = base64.b64encode(f.read()).decode()
                    with open(shared_key_path, "rb") as f:
                        encrypted_key = base64.b64encode(f.read()).decode()
                    return ReadFileResponse(encrypted_file=encrypted_file, encrypted_key=encrypted_key)
                except Exception as e:
                    # print(f"✗ Erro ao ler arquivo: {e}")
                    raise HTTPException(status_code=500, detail=f"Erro ao ler ficheiro partilhado: {e}")
            else:
                # print("✗ Arquivo ou chave não encontrados neste caminho")
                pass

    # print("✗ Arquivo não encontrado em nenhum compartilhamento")
    raise HTTPException(status_code=404, detail="Ficheiro não encontrado")
        
@app.post("/share/init", response_model=dict)
def share_init(data: ShareInitRequest, current_user: str = Depends(get_current_user)):
    filename = data.filename
    target_email = data.target_email

    # Verificações
    file_path = os.path.join("DB", current_user, "OWNER", "FILES", filename + ".encrypted")
    key_path = os.path.join("DB", current_user, "OWNER", "KEYS", filename + ".key.encrypted")
    if not os.path.exists(file_path) or not os.path.exists(key_path):
        raise HTTPException(status_code=404, detail="Ficheiro não encontrado.")

    # Obter chave pública do target
    target_pubkey = server.get_public_key(target_email)
    if not target_pubkey:
        raise HTTPException(status_code=404, detail="Chave pública do utilizador destino não encontrada.")

    # Ler chave AES cifrada
    with open(key_path, 'rb') as f:
        encrypted_key = f.read()

    # Codificar e devolver
    return {
        "filename": filename,
        "target_email": target_email,
        "target_public_key": base64.b64encode(target_pubkey).decode(),
        "encrypted_key": base64.b64encode(encrypted_key).decode()
    }    

@app.post("/share/complete", response_model=dict)
def share_complete(data: ShareCompleteRequest, current_user: str = Depends(get_current_user)):
    filename = data.filename
    target_email = data.target_email
    encrypted_key = base64.b64decode(data.encrypted_key_for_target)

    # Guardar permissões no JSON
    server.add_file_permission(current_user, filename, target_email, data.permissions)

    # Criar pasta de partilha se não existir
    shared_folder = os.path.join("DB", target_email, "SHARED_WITH", current_user)
    os.makedirs(shared_folder, exist_ok=True)

    # Guardar chave re-encriptada
    shared_key_path = os.path.join(shared_folder, filename + ".key.encrypted")
    # Garante que todos os diretórios anteriores existem
    os.makedirs(os.path.dirname(shared_key_path), exist_ok=True)
    # Cria o ficheiro e escreve a chave encriptada
    with open(shared_key_path, 'wb') as f:
        f.write(encrypted_key)

    # Copiar ficheiro cifrado também - NAO DEVE SER COPIADO O FICHEIRO - DEVE APENAS HAVER UMA VERSÃO
    original_path = os.path.join("DB", current_user, "OWNER", "FILES", filename + ".encrypted")
    shared_path = os.path.join(shared_folder, filename)
    with open(original_path, 'rb') as f_in, open(shared_path, 'wb') as f_out:
        f_out.write(f_in.read())

    return {"message": f"Ficheiro '{filename}' partilhado com {target_email} com sucesso."}

@app.get("/permissions", response_model=Dict[str, Dict[str, List[str]]])
def get_permissions(current_user: str = Depends(get_current_user)):

    try:
        permissions = server.get_permissions(current_user)
        return permissions
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao obter permissões: {e}")
    
@app.post("/append", response_model=dict)
def append_to_file(data: AppendData, current_user: str = Depends(get_current_user)):

    # Diretórios
    files_dir = os.path.join("DB", current_user, "OWNER", "FILES")
    keys_dir = os.path.join("DB", current_user, "OWNER", "KEYS")
    
    # Caminhos
    encrypted_file_path = os.path.join(files_dir, data.filename + ".encrypted")
    encrypted_key_path = os.path.join(keys_dir, data.filename + ".key.encrypted")
    
    # Verificar se o arquivo existe
    if not os.path.exists(encrypted_file_path):
        raise HTTPException(status_code=404, detail=f"Arquivo '{data.filename}' não encontrado.")
    
    # Verificar se não é uma pasta
    if os.path.isdir(encrypted_file_path):
        raise HTTPException(status_code=400, detail=f"'{data.filename}' é uma pasta. O comando append funciona apenas com arquivos.")
    
    try:
        # Ler o conteúdo atual do arquivo
        with open(encrypted_file_path, "rb") as f:
            current_encrypted_content = f.read()
        
        # Decodificar o novo conteúdo a ser adicionado
        new_encrypted_content = base64.b64decode(data.encrypted_file)
        
        # Combinar os conteúdos (atual + novo)
        combined_encrypted_content = current_encrypted_content + new_encrypted_content
        
        # Sobrescrever o arquivo com o conteúdo combinado
        with open(encrypted_file_path, "wb") as f:
            f.write(combined_encrypted_content)
  
        # Retornar estatísticas sobre a operação
        return {
            "message": f"Conteúdo adicionado com sucesso ao arquivo '{data.filename}'.",
            "original_size": len(current_encrypted_content),
            "added_size": len(new_encrypted_content),
            "new_total_size": len(combined_encrypted_content)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao adicionar conteúdo ao arquivo: {str(e)}")
    
@app.post("/append", response_model=dict)
def append_file(data: WriteData, current_user: str = Depends(get_current_user)):

    # Diretórios
    files_dir = os.path.join("DB", current_user, "OWNER", "FILES")
    keys_dir = os.path.join("DB", current_user, "OWNER", "KEYS")
    
    # Caminhos
    encrypted_file_path = os.path.join(files_dir, data.filename + ".encrypted")
    encrypted_key_path = os.path.join(keys_dir, data.filename + ".key.encrypted")
    
    # Verificar se o ficheiro existe
    if not os.path.exists(encrypted_file_path):
        raise HTTPException(status_code=404, detail=f"Ficheiro '{data.filename}' não encontrado.")
    
    try:
        # Ler a chave criptografada existente
        with open(encrypted_key_path, "rb") as f:
            encrypted_key = f.read()
        
        # Decodificar a chave fornecida pelo cliente (que deve ser a mesma)
        client_encrypted_key = base64.b64decode(data.encrypted_key)
        
        # Verificar se as chaves correspondem
        if encrypted_key != client_encrypted_key:
            raise HTTPException(status_code=400, detail="A chave fornecida não corresponde à chave original do arquivo.")
        
        # Ler o conteúdo encriptado original
        with open(encrypted_file_path, "rb") as f:
            original_encrypted_content = f.read()
        
        # Tamanho original para informação
        original_size = len(original_encrypted_content)
        
        # Decodificar o novo conteúdo a ser adicionado
        append_encrypted_content = base64.b64decode(data.encrypted_file)
        
        # Tamanho do conteúdo adicionado para informação
        added_size = len(append_encrypted_content)
        
        with open(encrypted_file_path, "wb") as f:
            f.write(original_encrypted_content + append_encrypted_content)
        
        return {
            "message": f"Conteúdo adicionado ao ficheiro '{data.filename}' com sucesso.",
            "original_size": original_size,
            "added_size": added_size,
            "new_total_size": original_size + added_size
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao adicionar conteúdo ao ficheiro: {e}")

@app.post("/append_folder", response_model=dict)
def append_folder(data: dict, current_user: str = Depends(get_current_user)):

    folder_name = data.get("folder")
    if not folder_name:
        raise HTTPException(status_code=400, detail="Nome da pasta não especificado.")
    
    new_files = data.get("files", [])
    encrypted_metadata = data.get("encrypted_metadata")
    encrypted_key = data.get("encrypted_key")
    
    if not encrypted_metadata or not encrypted_key:
        raise HTTPException(status_code=400, detail="Metadata da pasta não fornecido.")
    
    # Diretórios
    files_dir = os.path.join("DB", current_user, "OWNER", "FILES", folder_name)
    
    # Verificar se a pasta existe
    if not os.path.isdir(files_dir):
        raise HTTPException(status_code=404, detail=f"Pasta '{folder_name}' não encontrada.")
    
    try:
        # Atualizar o arquivo de metadata
        metadata_file_path = os.path.join("DB", current_user, "OWNER", "FILES", folder_name, ".metadata.encrypted")
        metadata_key_path = os.path.join("DB", current_user, "OWNER", "KEYS", folder_name, ".metadata.key.encrypted")
        
        with open(metadata_file_path, "wb") as f:
            f.write(base64.b64decode(encrypted_metadata))
        
        with open(metadata_key_path, "wb") as f:
            f.write(base64.b64decode(encrypted_key))
        
        # Contabilizar arquivos adicionados
        added_count = len(new_files)
        
        return {
            "message": f"Pasta '{folder_name}' atualizada com sucesso.",
            "added_files": added_count
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao atualizar pasta: {e}")
    
if __name__ == "__main__":
    # Cria o contexto SSL
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    
    # Configura o TLS 1.3
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
    ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
    
    # Carrega os certificados
    ssl_context.load_cert_chain(
        certfile="../certs/server.crt", 
        keyfile="../certs/key.crt"  
    )
    
    # Inicia o servidor
    uvicorn.run(
        "main_api:app",
        host="localhost",
        port=8443, 
        ssl_certfile="../certs/server.crt",
        ssl_keyfile="../certs/key.crt",
        ssl_version=ssl.PROTOCOL_TLS_SERVER
    )