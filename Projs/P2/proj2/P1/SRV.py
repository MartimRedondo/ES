import asyncio
import ssl
import uuid
import os
import base64
from argon2 import PasswordHasher, exceptions
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from secrets import token_hex
import json
from colorama import init, Fore, Back, Style

import HMAC as hhs
import RSA as rsa
from session_manager import session_manager

init(autoreset=True)

CONFIG = {
    'conn_port': 8443,
    'max_msg_size': 9999,
    'db_root': 'DB',
    'db_user_root': 'DB_USER'
}

STORAGE = {
    'accounts': {}, # [((name, email), pass_hash), ...]
    'user_ids': {}  # [(email, id), ...]
}

#HMAC_KEY = hhs.key_exists(filename="hmac/shared_hmac_key.json")

class ServerWorker:
    def __init__(self, addr=None):
        self.addr = addr
        self.nonces = {}
        self.ph = PasswordHasher()

    def generate_nonce(self, email):
        nonce = os.urandom(16).hex()
        self.nonces[email] = nonce
        return nonce
    
#-------------------------------------------------------#
#                         SERVER                        #
#                       VERIFGY NONCE                   #
# ------------------------------------------------------# 

    def verify_nonce(self, email, client_hmac, password):
        if email not in self.nonces:
            print(Fore.RED + "Nonce not found")
            return False
        
        nonce = self.nonces[email]
        message = password + nonce
        expected_hmac = hhs.create_hmac_signature(message, HMAC_KEY)

        if client_hmac != expected_hmac:
            print(Fore.RED + "HMAC verification failed")
            return False

        del self.nonces[email]
        return True
    
#-------------------------------------------------------#
#                         SERVER                        #
#                    INICIALIZAR O USER                 #
# ------------------------------------------------------#
    
    def create_directory_structure(self, email):
        self._ensure_directory(CONFIG['db_root'])
        
        base_path = os.path.join(CONFIG['db_root'], email)
        owner_path = os.path.join(base_path, "OWNER")
        
        paths = [
            os.path.join(owner_path, "FILES"),
            os.path.join(owner_path, "KEYS"),
            os.path.join(base_path, "SHARED_WITH")
        ]
        
        for path in paths:
            self._ensure_directory(path)
            
        print(Fore.LIGHTBLACK_EX + f"Directory structure created for {email} at {CONFIG['db_root']}/{email}")
        
        self._ensure_directory(CONFIG['db_user_root'])
        user_local_path = os.path.join(CONFIG['db_user_root'], email)
        self._ensure_directory(user_local_path)
        
        print(Fore.LIGHTBLACK_EX + f"Directory structure created for {email} at {CONFIG['db_user_root']}/{email}")

    
    @staticmethod
    def _ensure_directory(path):
        if not os.path.exists(path):
            os.makedirs(path)
            print(Back.CYAN + f"Directory '{path}' created.")

#-------------------------------------------------------#
#                         SERVER                        #
#                      DECRYPT PASS                     #
# ------------------------------------------------------#

    def decrypt_password(self, encrypted_password):
        cifra_rsa = rsa.carregar_chave_privada()
        pass_cifrada = base64.b64decode(encrypted_password)
        return cifra_rsa.decrypt(pass_cifrada).decode()
    
#-------------------------------------------------------#
#                         SERVER                        #
#                       REGISTRATION                    #
# ------------------------------------------------------#

    def register_user(self, name, password, email):
        if (name, email) in STORAGE['accounts']:
            print(Fore.RED + "Email already registered")
            return "Email already registered"
        
        # Gerar UUID para o usuário
        user_uuid = uuid.uuid4()
        STORAGE['user_ids'][email] = user_uuid
        print(Fore.LIGHTBLACK_EX + "User ID generated:", user_uuid)
        
        decrypted_password = self.decrypt_password(password)
        password_hash = self.ph.hash(decrypted_password)
        STORAGE['accounts'][(name, email)] = password_hash
        print(Back.CYAN + "User registered:", name, email)

        self.create_directory_structure(email)

        return f"User {name} registered successfully"
    
#-------------------------------------------------------#
#                         SERVER                        #
#                       LOGIN USER                      #
# ------------------------------------------------------#
    
    def login_user(self, password_attempt, email, client_hmac):
        user_found = None
        for (name, mail), stored_hash in STORAGE['accounts'].items():
            if mail == email:
                user_found = ((name, mail), stored_hash)
                break

        if not user_found:
            print(Fore.RED + "Email not registered")
            return "Email not registered", None
        print(Fore.LIGHTBLACK_EX + f"User found: {user_found[0][0]}")

        # Verificar HMAC
        if not self.verify_nonce(email, client_hmac, password_attempt):
            print(Fore.RED + "HMAC verification failed")
            return "HMAC verification failed", None
        print(Fore.LIGHTBLACK_EX + "HMAC verification successful")

        # Verificar senha
        try: 
            decrypted_password = self.decrypt_password(password_attempt)
            self.ph.verify(user_found[1], decrypted_password)
        except exceptions.VerifyMismatchError:
            print(Fore.RED + "Password verification failed")
            return "Password verification failed", None
        except exceptions.InvalidHash:
            print(Fore.RED + "Invalid hash")
            return "Invalid hash", None
        except Exception as e:
            print(Fore.RED + f"Unexpected error: {e}")
            return "Unexpected error", None
        
        print(Back.CYAN + "Password verification successful")

        # Criar sessão
        session_token = token_hex(16)
        print(f"Session token: {session_token}")
        session_manager.create_session(email, session_token)
        print(Back.GREEN + "Login successful for:", email)
        
        return "Login successful!", session_token
    
#-------------------------------------------------------#
#                         SERVER                        #
#                       LIST FILES                      #
# ------------------------------------------------------#

    def list_user_files(self, email):
        user_dir = f"{CONFIG['db_root']}/{email}/OWNER/FILES"
        os.makedirs(user_dir, exist_ok=True)
        files = os.listdir(user_dir)
        print(Fore.LIGHTBLACK_EX + f"Files in {user_dir}: {files}")
        return "\t".join(files)
    

#-------------------------------------------------------#
#                         SERVER                        #
#                        PERMISSÕES                     #
#-------------------------------------------------------#

    # def create_permission_file(self, email):
    #     permission_path = os.path.join(CONFIG['db_root'], email, "OWNER", "permissions.json")
    #     if not os.path.exists(permission_path):
    #         default_permissions = {}
    #         with open(permission_path, 'w') as f:
    #             json.dump(default_permissions, f)
    #         print(Fore.LIGHTBLACK_EX + f"Permission file created for {email}")
    #     return permission_path

    def create_permission_file(self, email):
        permission_path = os.path.join(CONFIG['db_root'], email, "OWNER", "permissions.json")
        if not os.path.exists(permission_path):
            default_permissions = {}
            os.makedirs(os.path.dirname(permission_path), exist_ok=True)
            with open(permission_path, 'w') as f:
                json.dump(default_permissions, f)
            print(Fore.LIGHTBLACK_EX + f"Permission file created for {email}")
        return  # não retorna nada

    def get_permissions(self, owner_email):
        permission_path = os.path.join(CONFIG['db_root'], owner_email, "OWNER", "permissions.json")

        if not os.path.exists(permission_path):
            self.create_permission_file(owner_email)
            return {}

        try:
            with open(permission_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(Fore.RED + f"Erro ao ler ficheiro de permissões: {e}")
            return {}

    def save_permissions(self, owner_email, permissions):
        permission_path = os.path.join(CONFIG['db_root'], owner_email, "OWNER", "permissions.json")
        os.makedirs(os.path.dirname(permission_path), exist_ok=True)
        with open(permission_path, 'w') as f:
            json.dump(permissions, f, indent=4)
        print(Back.GREEN + f"Permissions updated for {owner_email}")

    def add_file_permission(self, owner_email, filename, target_email, permissions):
        current_permissions = self.get_permissions(owner_email)

        if filename not in current_permissions:
            current_permissions[filename] = {}

        current_permissions[filename][target_email] = permissions
        self.save_permissions(owner_email, current_permissions)

        shared_folder = os.path.join(CONFIG['db_root'], target_email, "SHARED_WITH")
        self._ensure_directory(shared_folder)

        return True

    def check_permission(self, owner_email, filename, user_email, required_permission):
        if owner_email == user_email: #owner full permissions
            return True

        permissions = self.get_permissions(owner_email)
        if filename not in permissions:
            return False

        if user_email not in permissions[filename]:
            return False

        return required_permission in permissions[filename][user_email]

    # def get_public_key(self, email):
    #     user_dir = os.path.join(CONFIG['db_user_root'], email, "keys")
    #     if not os.path.exists(user_dir):
    #         return None
    #     key_path = os.path.join(user_dir, "public_key.pem")
    #     if not os.path.exists(key_path):
    #         return None
    #     with open(key_path, 'rb') as f:
    #         return f.read()

    def get_public_key(self, email):

        # Caminho correto baseado no email "seguro"
        user_dir = os.path.join("DB", email, "keys")
        key_path = os.path.join(user_dir, "public_key.pem")

        # DEBUG
        print(f"[DEBUG] A procurar chave pública em: {key_path}")

        if not os.path.exists(key_path):
            return None

        with open(key_path, 'rb') as f:
            return f.read()

#-------------------------------------------------------#
#                         SERVER                        #
#                      LIST SHARED FILES                #
#-------------------------------------------------------#

    def list_shared_files(self, user_email):
        shared_files = []
        for owner_folder in os.listdir(CONFIG['db_root']):
            owner_path = os.path.join(CONFIG['db_root'], owner_folder)
            if not os.path.isdir(owner_path) or owner_folder == user_email:
                continue
            permission_path = os.path.join(owner_path, "OWNER", "permissions.json")
            if not os.path.exists(permission_path):
                continue
            try:
                with open(permission_path, 'r') as f:
                    permissions = json.load(f)
                for filename, file_perms in permissions.items():
                    if user_email in file_perms:
                        shared_files.append({
                            "owner": owner_folder,
                            "filename": filename,
                            "permissions": file_perms[user_email]
                        })
        
            except:
                continue
        #print(Back.CYAN + f"Shared files for {user_email}: {shared_files}")
        return shared_files
    
#-------------------------------------------------------#
#                         SERVER                        #
#                       JUST SHARED                     #
#-------------------------------------------------------#

    def _handle_share_file(self, msg):
        owner_email, token, filename, target_email, permissions = msg[1], msg[2], msg[3], msg[4], msg[5].split(",")
        if not session_manager.is_authenticated(owner_email, token):
            print(Fore.RED + "Permission denied")
            return "Unauthorized".encode()

        file_path = os.path.join(CONFIG['db_root'], owner_email, "OWNER", "FILES", filename)
        #print (Back.YELLOW + f"File path: {file_path}")
        filename = filename.replace(".encrypted", "")
        key_path = os.path.join(CONFIG['db_root'], owner_email, "OWNER", "KEYS", filename + ".key.encrypted")
        #print (Back.YELLOW + f"Key path: {key_path}")

        if not os.path.exists(file_path) or not os.path.exists(key_path):
            return f"Error: File {filename} does not exist".encode()

        target_public_key = self.get_public_key(target_email)
        if not target_public_key:
            return f"Error: Public key for {target_email} not found".encode()

        success = self.add_file_permission(owner_email, filename, target_email, permissions)

        if success:
            shared_folder = os.path.join(CONFIG['db_root'], target_email, "SHARED_WITH", owner_email)
            self._ensure_directory(shared_folder)

            with open(file_path, 'rb') as f:
                encrypted_file = f.read()

            with open(key_path, 'rb') as f:
                encrypted_key = f.read()

            public_key_b64 = base64.b64encode(target_public_key).decode()
            encrypted_key_b64 = base64.b64encode(encrypted_key).decode()

            data = f"ShareFileSucess||BRUH||{filename}\t{target_email}\t{public_key_b64}|\t{encrypted_key_b64}"
            print(Fore.LIGHTBLACK_EX + f"File {filename} shared with {target_email} successfully")
            return data.encode()
        else:
            return "Error sharing file".encode()
        
    def handle_reshare_key(self, msg):
        owner_email, token, filename, target_email, encrypted_key_b64 = msg[1], msg[2], msg[3], msg[4], msg[5]

        if not session_manager.is_authenticated(owner_email, token):
            print(Fore.RED + "Permission denied")
            return "Unauthorized".encode()

        #print (Back.YELLOW + f"ReshareKey: {filename} to {target_email}")
        permissions = self.get_permissions(owner_email)
        if filename not in permissions or target_email not in permissions[filename]:
            return "Permission denied".encode()

        shared_key_path = os.path.join(CONFIG['db_root'], target_email, "SHARED_WITH", owner_email, filename + ".key.encrypted")

        try:
            encrypted_key = base64.b64decode(encrypted_key_b64)
            with open(shared_key_path, 'wb') as f:
                f.write(encrypted_key)
            print(Fore.LIGHTBLACK_EX + f"Key reshared successfully to {target_email}")

            source_file_path = os.path.join(CONFIG['db_root'], owner_email, "OWNER", "FILES", filename + ".encrypted")
            shared_file_path = os.path.join(CONFIG['db_root'], target_email, "SHARED_WITH", owner_email, filename)

            with open(source_file_path, 'rb') as src_f:
                encrypted_file = src_f.read()

            with open(shared_file_path, 'wb') as dst_f:
                dst_f.write(encrypted_file)

            print(Back.GREEN + f"File {filename} shared with {target_email} successfully")
            return f"ReshareKeySucess||BRUH||File {filename} shared with {target_email} successfully".encode()
        except Exception as e:
            print(f"Error resharing key: {e}")
            return f"Error: {str(e)}".encode()

    def _handle_list_shared(self, msg):
        email, token = msg[1], msg[2]

        if not session_manager.is_authenticated(email, token):
            print("Permission denied")
            return "Unauthorized".encode()
        
        #print (Back.YELLOW + "ENTREI NO HANDLE LIST SHARED")
        shared_files = self.list_shared_files(email)

        files_str = ""
        for file in shared_files:
            permissions_str = ",".join(file["permissions"])
            files_str += f"{file['owner']}|{file['filename']}|{permissions_str}\t"

        data = f"SharedFilesList||BRUH||{files_str}"
        #print(Back.CYAN + f"Shared files for {email}: {data}")
        return data.encode()

    def _handle_request_file(self, msg):
        email, token, owner_email, filename = msg[1], msg[2], msg[3], msg[4]

        if not session_manager.is_authenticated(email, token):
            print(Fore.RED + "Permission denied")
            return "Unauthorized".encode()

        if not self.check_permission(owner_email, filename, email, "READ"):
            print(Fore.RED + "Permission denied")
            return "Unauthorized: No READ permission".encode()

        if owner_email == email:
            file_path = os.path.join(CONFIG['db_root'], owner_email, "OWNER", "FILES", filename)
            key_path = os.path.join(CONFIG['db_root'], owner_email, "OWNER", "KEYS", filename + ".key.encrypted")
        else:
            file_path = os.path.join(CONFIG['db_root'], email, "SHARED_WITH", owner_email, filename)
            key_path = os.path.join(CONFIG['db_root'], email, "SHARED_WITH", owner_email, filename + ".key.encrypted")

        if not os.path.exists(file_path) or not os.path.exists(key_path):
            print(Fore.RED + f"File {filename} does not exist")
            return f"Error: File {filename} does not exist".encode()

        with open(file_path, 'rb') as f:
            file_data = f.read()

        with open(key_path, 'rb') as f:
            key_data = f.read()

        file_data_b64 = base64.b64encode(file_data).decode()
        key_data_b64 = base64.b64encode(key_data).decode()

        data = f"RequestFileSucess||BRUH||{filename}||{file_data_b64}||{key_data_b64}"
        print(Fore.LIGHTBLACK_EX + f"File {filename} requested successfully")
        return data.encode()
        
#-------------------------------------------------------#
#                         SERVER                        #
#                       UPLOAD FILE                     #
# ------------------------------------------------------#

    def handle_file_upload(self, email, data, is_key=False):
        folder = "KEYS" if is_key else "FILES"
        path = f"{CONFIG['db_root']}/{email}/OWNER/{folder}/{data}"
        with open(path, "wb") as f:
            f.write(base64.b64decode(data))
        return "Upload successful"


#-------------------------------------------------------#
#                         SERVER                        #
#                      HANDLES CLIENT                   #
# ------------------------------------------------------#

    def _handle_register(self, msg):
        print(Fore.LIGHTBLACK_EX + "Processing registration for:", msg[1])
        response = self.register_user(msg[1], msg[2], msg[3])
        data = f"RegisterSucess||BRUH||{response}\t{msg[3]}"
        return data.encode()
    
    def _handle_login_request(self, msg):
        nonce = self.generate_nonce(msg[1])
        data = f"LoginRequestSucess||BRUH||{nonce}"
        return data.encode()
    
    def _handle_login(self, msg):
        print(Fore.LIGHTBLACK_EX + "Processing login for:", msg[2])
        response, session_token = self.login_user(msg[1], msg[2], msg[3])
        if response.startswith("Login successful!"):
            return f"LoginSucess||BRUH||{msg[2]}\t{session_token}".encode()
        return response.encode()
    
    def _handle_list_files(self, msg):
        email, token = msg[1], msg[2]
        print(f"Email: {email}")
        print(f"Token: {token}")
        
        if session_manager.is_authenticated(email, token):
            files = self.list_user_files(email)
            data = f"FilesList||BRUH||{files}".encode()
            return data
        else:
            print(Fore.RED + "Permission denied")
            return "Unauthorized".encode()
    
    def _handle_inicio_upload(self, msg):
        email, token, nome_arquivo = msg[1], msg[2], msg[3]

        if not session_manager.is_authenticated(email, token):
            print(Fore.RED + "Permission denied")
            return "Unauthorized".encode()

        file_dir = f"{CONFIG['db_root']}/{email}/OWNER/FILES"
        key_dir = f"{CONFIG['db_root']}/{email}/OWNER/KEYS"

        os.makedirs(file_dir, exist_ok=True)
        os.makedirs(key_dir, exist_ok=True)

        self.temp_file_path = os.path.join(file_dir, nome_arquivo + ".tmp")
        self.final_file_path = os.path.join(file_dir, nome_arquivo + ".encrypted")
        self.key_file_path = os.path.join(key_dir, nome_arquivo + ".key.encrypted")

        if os.path.exists(self.temp_file_path):
            os.remove(self.temp_file_path)

        print(f"Iniciando upload para arquivo: {nome_arquivo}")
        data = f"InicioUploadSucess||BRUH||{email}"
        return data.encode()

    def _handle_upload(self, msg):
        email, token, chunk = msg[1], msg[2], msg[3]
        if not session_manager.is_authenticated(email, token):
            print(Fore.RED + "Permission denied")
            return "Unauthorized".encode()

        try:
            chunk_data = base64.b64decode(chunk)
            with open(self.temp_file_path, "ab") as f:
                f.write(chunk_data)

            print(Fore.LIGHTBLACK_EX + f"Chunks recebidos: {len(chunk_data)} bytes")
            data = f"UploadSucess||BRUH||Chunk received"
            return data.encode()
        except Exception as e:
            print(f"Erro ao processar chunk: {e}")
            return f"Error: {str(e)}".encode()

    def _handle_upload_eof(self, msg):
        email, token = msg[1], msg[2]

        if not session_manager.is_authenticated(email, token):
            print(Fore.RED + "Permission denied")
            return "Unauthorized".encode()

        if os.path.exists(self.temp_file_path):
            os.rename(self.temp_file_path, self.final_file_path)
            print(Back.GREEN + f"Upload completo: {self.final_file_path}")

            data = f"UploadEOFSucess||BRUH||Upload complete"
            return data.encode()
        else:
            print(Fore.RED + "Error: No temporary file found")
            return "Error: No temporary file found".encode()

    def _handle_upload_key(self, msg):
        email, token, chave_b64 = msg[1], msg[2], msg[3]

        if not session_manager.is_authenticated(email, token):
            print(Fore.RED + "Permission denied")
            return "Unauthorized".encode()

        try:
            chave_data = base64.b64decode(chave_b64)
            with open(self.key_file_path, "wb") as f:
                f.write(chave_data)

            print(Fore.LIGHTBLACK_EX+ f"Chave cifrada salva: {self.key_file_path}")
            data = f"UploadKeySucess||BRUH||Key saved"
            return data.encode()
        except Exception as e:
            print(Fore.RED + f"Erro ao salvar chave: {e}")
            return f"Error: {str(e)}".encode()
    
    def _handle_logout(self, msg):
        email = msg[1]
        if session_manager.remove_session(email):
            return "Logout successful".encode()
        else:
            return "User not logged in".encode()
        
#-------------------------------------------------------#
#                         SERVER                        #
#                        PROCESS                        #
# ------------------------------------------------------#

    # Update the process method in SRV.py
    def process(self, msg):
        flag = msg[0]       
        command_handlers = {
            "Register": self._handle_register,
            "LoginRequest": self._handle_login_request,
            "Login": self._handle_login,
            "ListFiles": self._handle_list_files,
            "InicioUpload": self._handle_inicio_upload,
            "Upload": self._handle_upload,
            "UploadEOF": self._handle_upload_eof,
            "UploadKey": self._handle_upload_key,
            "Logout": self._handle_logout,
            "ShareFile": self._handle_share_file,
            "ReshareKey": self.handle_reshare_key,
            "ListSharedFiles": self._handle_list_shared,
            "RequestFile": self._handle_request_file,
        }
        handler = command_handlers.get(flag)
        if handler:
            return handler(msg)
        else:
            print("Unknown command:", flag)
            return b"Unknown command"

#-------------------------------------------------------#
#                         SERVER                        #
#                     HANDLE CONNECTION                 #
# ------------------------------------------------------#

async def handle_client_connection(reader, writer):
    addr = writer.get_extra_info('peername')
    server_worker = ServerWorker(addr)

    while True:
        data = await reader.read(CONFIG['max_msg_size'])
        if not data or data[:1] == b'\n':
            break
            
        data_str = data.decode()
        #print(Fore.GREEN + f"Received {data_str}")

        if "||HMAC||" in data_str:
            message, hmac_signature = data_str.split("||HMAC||", 1)
            #print(Fore.CYAN + f"Received {message}")
            
            if not hhs.verify_hmac_signature(message, hmac_signature, HMAC_KEY):
                print(Fore.RED + "HMAC verification failed")
                response = "HMAC verification failed - security violation".encode()

            else:
                parts = message.split("\t")
                response = server_worker.process(parts)
        else:
            print(Fore.YELLOW + "Warning: Message received without HMAC signature")
            parts = data_str.split("\t")
            response = server_worker.process(parts)
        
        # Envio da resposta com assinatura HMAC
        if response:
            response_text = response.decode()
            hmac_signature = hhs.create_hmac_signature(response_text, HMAC_KEY)
            full_response = f"{response_text}||HMAC||{hmac_signature}".encode()
            
            writer.write(full_response)
            await writer.drain()

    writer.close()

#-------------------------------------------------------#
#                         SERVER                        #
#                       SSL CONTEXT                    #
# ------------------------------------------------------#

def setup_ssl_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile="server.crt", keyfile="server.key")
    return ctx

#-------------------------------------------------------#
#                         SERVER                        #
#                       RUN SERVER                     #
# ------------------------------------------------------#

def run_server():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    server_ssl_ctx = setup_ssl_context()
    coro = asyncio.start_server(
        handle_client_connection, 
        '127.0.0.1', 
        CONFIG['conn_port'], 
        ssl=server_ssl_ctx
    )

    server = loop.run_until_complete(coro)
    print(f'Server running on {server.sockets[0].getsockname()[0]}:{server.sockets[0].getsockname()[1]}')
    print('  (press Ctrl+C to stop)\n')

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
    finally:
        server.close()
        loop.run_until_complete(server.wait_closed())
        loop.close()
        print('Server stopped!')

if __name__ == "__main__":
    run_server()