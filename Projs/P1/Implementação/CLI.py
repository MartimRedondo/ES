import asyncio
import ssl
import re
from secrets import token_hex
import base64
import os
import HMAC as hhs
import RSA as rsa
import HelpToUpload as up
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from colorama import init, Fore, Back, Style

init(autoreset=True)

conn_port = 8443
max_msg_size = 9999

login_attempts = {}  
lockout_time = 300 
sessions = {}

HMAC_KEY = hhs.key_exists(filename="hmac/shared_hmac_key.json")

class Client:
    def __init__(self, sckt=None):
        self.sckt = sckt
        self.reader = None
        self.writer = None
        self.authenticated = False
        self.nome_cliente = ""

    def valida_email(self, email):
        regex_email = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
        if not re.match(regex_email, email):
            return False, "Formato de e-mail inválido."
        
        return True, None

    def valida_senha(self, senha):
        erros = []

        if len(senha) < 8:
            erros.append("A senha deve ter no mínimo 8 caracteres.")

        if not re.search(r"[A-Z]", senha):
            erros.append("A senha deve conter ao menos uma letra maiúscula.")

        if not re.search(r"[a-z]", senha):
            erros.append("A senha deve conter ao menos uma letra minúscula.")

        if not re.search(r"\d", senha):
            erros.append("A senha deve conter ao menos um dígito.")

        if not re.search(r"[^\w\s]", senha):
            erros.append("A senha deve conter ao menos um símbolo (caractere especial).")

        if erros:
            return False, " ".join(erros)
        else:
            return True, None

    def validate(self, senha, email):
        boolE, errosE = self.valida_email(email)
        if not boolE:
            print(Fore.RED + f"Erro no e-mail: {errosE}")
            return False

        boolS, errosS = self.valida_senha(senha)
        if not boolS:
            print(Fore.RED + f"Erro na senha: {errosS}")
            return False
        return True

    def HMAC(self, data):
        hmac_sign = hhs.create_hmac_signature(data, HMAC_KEY)
        full_data = f"{data}||HMAC||{hmac_sign}"
        return full_data.encode()
    
#-------------------------------------------------------#
#                         Conexão                       #
# ------------------------------------------------------# 

    async def connect(self):
        client_ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3  
        
        client_ssl_ctx.load_verify_locations("ca.crt")
        
        client_ssl_ctx.check_hostname = False 
        client_ssl_ctx.verify_mode = ssl.CERT_REQUIRED 

        self.reader, self.writer = await asyncio.open_connection(
            '127.0.0.1', conn_port, ssl=client_ssl_ctx
        )
        
        self.sckt = self.writer.get_extra_info('peername')

#-------------------------------------------------------#
#                         CLIENTE                       #
#                        SEND MSG                       #
# ------------------------------------------------------# 

    async def send_message(self, message):
        self.writer.write(message)
        await self.writer.drain()

#-------------------------------------------------------#
#                         CLIENTE                       #
#                        RECEIVE MSG                    #
# ------------------------------------------------------# 

    async def receive_message(self):
        msg = await self.reader.read(max_msg_size)
        decoded_msg = msg.decode()
        
        if "||HMAC||" in decoded_msg:
            response, hmac_signature = decoded_msg.split("||HMAC||", 1)
            
            if hhs.verify_hmac_signature(response, hmac_signature, HMAC_KEY):
                response_parts = response.split("||BRUH||", 1)
                return True, response_parts
            else:
                print(Fore.YELLOW + "AVISO: Verificação HMAC falhou - possível adulteração da mensagem!")
                print(Fore.YELLOW + "Mensagem recebida (NÃO CONFIÁVEL):", response)
                return False, None
        else:
            print(Fore.YELLOW + "AVISO: Resposta sem HMAC recebida")
            print(Fore.YELLOW + "Mensagem recebida (NÃO CONFIÁVEL):", decoded_msg)
            return False, None

    #-------------------------------------------------------#
    #                         CLIENTE                       #
    #                       SHARED FILES                    #
    # ------------------------------------------------------# 

    async def share_file(self, filename):
        email = self.nome_cliente
        if email not in sessions:
            print(Fore.RED + "Sessão inválida. Faça login novamente.")
            return False

        token = sessions[email]
        target_email = input("Digite o email do utilizador com quem deseja partilhar: ")
        if not self.valida_email(target_email):
            print(Fore.RED + "Formato de e-mail inválido.")
            return False

        print(Style.BRIGHT + Fore.YELLOW + """
              Permissões disponíveis:
              (1) Ler (READ)
              (2) Ler e Escrever (READ,WRITE)
              """)
        permissions = ""

        perm_choice = input("Escolha uma opção (1/2): ")
        if perm_choice == "1":
            permissions = "READ"
        elif perm_choice == "2":
            permissions = "READ,WRITE"
        else:
            print(Fore.RED + "Opção inválida.")
            return False

        data = f"ShareFile\t{email}\t{token}\t{filename}\t{target_email}\t{permissions}"
        full_data = self.HMAC(data)

        await self.send_message(full_data)
        verified, response_parts = await self.receive_message()
        #print(Back.CYAN + f"Resposta do servidor: {response_parts}")

        if verified and response_parts[0] == "ShareFileSucess":
            filename, target_email, target_public_key_b64, encrypted_key_b64 = response_parts[1].split("\t")
            print (Back.LIGHTBLUE_EX + f"Ficheiro '{filename}' partilhado com {target_email} com permissões: {permissions}")
                   
            #target_public_key = base64.b64decode(target_public_key_b64)
            encrypted_key = base64.b64decode(encrypted_key_b64)

            user_dir = os.path.join("DB_USER", email, "keys")
            private_key_path = os.path.join(user_dir, "chave_privada.pem")

            try:
                with open(private_key_path, 'rb') as f:
                    private_key_data = f.read()

                new_key = up.transcifrar_chave_aes(encrypted_key,private_key_data, target_public_key_b64)

                new_key_b64 = base64.b64encode(new_key).decode()
                data = f"ReshareKey\t{email}\t{token}\t{filename}\t{target_email}\t{new_key_b64}"
                full_data = self.HMAC(data)
                #print(Back.YELLOW + f"ReshareKey: {full_data.decode()}")

                await self.send_message(full_data)
                verified, response_parts = await self.receive_message()

                if verified and response_parts[0] == "ReshareKeySucess":
                    print(Back.GREEN + f"Ficheiro '{filename}' partilhado com {target_email} com permissões: {permissions} com sucesso")
                    return True
                else:
                    print(Back.RED + "Erro ao completar o compartilhamento do ficheiro.")
                    return False

            except Exception as e:
                print(Back.RED + f"Erro ao processar as chaves: {e}")
                return False
        else:
            print(Back.RED + "Erro ao iniciar o compartilhamento do ficheiro.")
            return False

    async def request_file(self, owner_email, filename): # esta função é usada para pedir o ficheiro ao dono
        email = self.nome_cliente
        if email not in sessions:
            print(Fore.RED + "Sessão inválida. Faça login novamente.")
            return False

        token = sessions[email]
        data = f"RequestFile\t{email}\t{token}\t{owner_email}\t{filename}"
        full_data = self.HMAC(data)

        await self.send_message(full_data)
        verified, response_parts = await self.receive_message()

        if verified and response_parts[0] == "RequestFileSucess":
            filename, file_data_b64, key_data_b64 = response_parts[1].split("||")

            file_data = base64.b64decode(file_data_b64)
            key_data = base64.b64decode(key_data_b64)

            user_dir = os.path.join("DB_USER", email)
            os.makedirs(user_dir, exist_ok=True)

            if owner_email != email:
                shared_dir = os.path.join(user_dir, "SHARED", owner_email)
                os.makedirs(shared_dir, exist_ok=True)
                encrypted_file_path = os.path.join(shared_dir, filename + ".encrypted")
                key_file_path = os.path.join(shared_dir, filename + ".key.encrypted")
            else:
                encrypted_file_path = os.path.join(user_dir, filename + ".encrypted")
                key_file_path = os.path.join(user_dir, filename + ".key.encrypted")

            with open(encrypted_file_path, 'wb') as f:
                f.write(file_data)

            with open(key_file_path, 'wb') as f:
                f.write(key_data)

            print(Back.GREEN + f"Ficheiro '{filename}' recebido e guardado")

            private_key_path = os.path.join(user_dir, "chave_privada.pem")

            try:
                with open(private_key_path, 'rb') as f:
                    private_key_data = f.read()

                private_key = serialization.load_pem_private_key(
                    private_key_data,
                    password=None
                )

                with open(key_file_path, 'rb') as f:
                    encrypted_aes_key = f.read()

                aes_key = private_key.decrypt(
                    encrypted_aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                with open(encrypted_file_path, 'rb') as f:
                    encrypted_file = f.read()

                cipher = Cipher(algorithms.AES(aes_key), modes.CBC(b'\0' * 16))
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(encrypted_file) + decryptor.finalize()

                unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
                decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()

                if owner_email != email:
                    decrypted_path = os.path.join(shared_dir, filename)
                else:
                    decrypted_path = os.path.join(user_dir, filename)

                with open(decrypted_path, 'wb') as f:
                    f.write(decrypted_data)

                print(Fore.GREEN + f"Ficheiro decifrado com sucesso: {decrypted_path}")
                return True

            except Exception as e:
                print(Back.RED + f"Erro ao decifrar ficheiro: {e}")
                return False
        else:
            print(Back.RED + "Erro ao receber ficheiro.")
            return False

    async def handle_shared_files(self):
        shared_files = await self.list_shared_files()
        if not shared_files:
            print("Não há ficheiros partilhados consigo.")
            return

        print("\n===== Ficheiros partilhados consigo =====")
        for idx, file in enumerate(shared_files):
            perm_str = ", ".join(file["permissions"])
            print(f"{idx + 1}. {file['filename']} (Dono: {file['owner']}, Permissões: {perm_str})")

        print("\n=========================================")
        print("0. Voltar ao menu anterior")
        escolha = input("Escolha uma opção: ")

        if escolha == "0":
            return

        try:
            idx_escolhido = int(escolha) - 1
            if 0 <= idx_escolhido < len(shared_files):
                file = shared_files[idx_escolhido]
                while True:
                    print(Style.BRIGHT + Fore.YELLOW + f"""
                    +---------------------------------------------+
                    | MENU SHARED - Ficheiro: {file['filename']}
                    |---------------------------------------------|
                    | 1. Acessar ficheiro (READ)                  |
                    | 2. Modificar ficheiro (WRITE) - se permitido|
                    | 0. Voltar ao menu anterior                  |
                    +---------------------------------------------+
                    """)

                    acao = input("Escolha uma ação: ")

                    if acao == "1":
                        await self.request_file(file['owner'], file['filename'])
                    elif acao == "2":
                        if "WRITE" in file['permissions']:
                            print("[WRITE] Funcionalidade a ser implementada...")
                        else:
                            print(Back.RED + "Você não tem permissão de escrita para este arquivo.")
                    elif acao == "0":
                        break
                    else:
                        print("Ação inválida.")

            else:
                print("Opção inválida.")
        except ValueError:
            print("Opção inválida.")

    async def list_shared_files(self):
        email = self.nome_cliente
        if email not in sessions:
            print(Fore.RED + "Sessão inválida. Faça login novamente.")
            return False
            
        token = sessions[email]
        data = f"ListSharedFiles\t{email}\t{token}"
        full_data = self.HMAC(data)
        
        await self.send_message(full_data)
        verified, response_parts = await self.receive_message()
        
        if verified and response_parts[0] == "SharedFilesList":
            files = response_parts[1].split("\t")
            shared_files = []
            #print (Back.YELLOW + f"Ficheiros partilhados recebidos: {files}")
            for file_info in files:
                if (file_info != ""):
                    #print (Back.YELLOW + f"Ficheiro partilhado: {file_info}")
                    owner, filename, permissions = file_info.split("|")
                    shared_files.append({"filename": filename, "owner": owner, "permissions": permissions.split(",")})
            return shared_files
        else:
            print(Back.RED + "Erro ao receber lista de ficheiros partilhados.")
            return None
        
#-------------------------------------------------------#
#                         CLIENTE                       #
#                       UPLOAD FILE                     #
# ------------------------------------------------------#
        
    async def upload_file(self, email, token, temp_file_path=None, temp_key_path=None, filename=None):
        if temp_file_path and temp_key_path and filename:
            with open(temp_file_path, 'rb') as f:
                arquivo_cifrado = f.read()
            with open(temp_key_path, 'rb') as f:
                chave_cifrada = f.read()
        else:
            user_files_path = os.path.join("DB_USER", email)
            try:
                ficheiros_locais = os.listdir(user_files_path)
                ficheiros_locais = [f for f in ficheiros_locais if os.path.isfile(os.path.join(user_files_path, f))]
            except FileNotFoundError:
                print(Fore.RED + "Diretório de ficheiros não encontrado.")
                return False
            if not ficheiros_locais:
                print(Fore.RED + "Não tem ficheiros locais para upload.")
                return False
            
            print("\n===== Ficheiros disponíveis para upload =====")
            for idx, file_name in enumerate(ficheiros_locais):
                print(f"{idx + 1}. {file_name}")
            print("0. Cancelar")
            print("==============================================")
            escolha_ficheiro = input("Escolha um ficheiro para fazer upload: ")

            # Opçõez
            if escolha_ficheiro == "0":
                return False
            try:
                idx_escolhido = int(escolha_ficheiro) - 1
                ficheiro_a_enviar = ficheiros_locais[idx_escolhido]
            except (ValueError, IndexError):
                print("Opção inválida.")
                return False
            
            caminho_ficheiro = os.path.join(user_files_path, ficheiro_a_enviar)
            try:
                with open(caminho_ficheiro, "rb") as f:
                    conteudo = f.read()
            except Exception as e:
                print(f"Erro ao ler ficheiro: {e}")
                return False
            print(Fore.LIGHTBLACK_EX + f"Ficheiro escolhido: {caminho_ficheiro}")
            if not os.path.exists(email):
                os.makedirs(email)

            keys_path = os.path.join("DB_USER", email, "keys")
            temp_path = os.path.join(user_files_path, "encrypted")

            os.makedirs(keys_path, exist_ok=True)
            os.makedirs(temp_path, exist_ok=True)
            #print (Back.CYAN + f"Chaves criadas para o ficheiro: {keys_path}")

            chave_privada_rsa, chave_publica_rsa = up.carregar_chaves_rsa(keys_path)
            caminho_cifrado, caminho_chave_cifrada, chave_aes = up.cifrar_arquivo(caminho_ficheiro, temp_path, chave_publica_rsa)

            with open(caminho_cifrado, 'rb') as f:
                arquivo_cifrado = f.read()
            with open(caminho_chave_cifrada, 'rb') as f:
                chave_cifrada = f.read()
            filename = os.path.basename(caminho_ficheiro)

        data = f"InicioUpload\t{email}\t{token}\t{filename}"
        full_data = self.HMAC(data)
        #print(Back.CYAN + f"Iniciando upload: {full_data.decode()}")
        await self.send_message(full_data)

        verified, response_parts = await self.receive_message()

        if verified and response_parts and "InicioUploadSucess" in response_parts[0]:
            arquivo_cifrado_b64 = base64.b64encode(arquivo_cifrado).decode()

            chunk_size = 4000
            for i in range(0, len(arquivo_cifrado_b64), chunk_size):
                chunk = arquivo_cifrado_b64[i:i + chunk_size]
                data = f"Upload\t{email}\t{token}\t{chunk}"
                full_data = self.HMAC(data)
                await self.send_message(full_data)

                verified, response_parts = await self.receive_message()
                if not verified or "UploadSucess" not in response_parts[0]:
                    print(Back.RED + "Erro ao enviar arquivo cifrado.")
                    return False
                
            data = f"UploadEOF\t{email}\t{token}"
            full_data = self.HMAC(data)
            await self.send_message(full_data)
            verified, response_parts = await self.receive_message()

            chave_cifrada_b64 = base64.b64encode(chave_cifrada).decode()
            data = f"UploadKey\t{email}\t{token}\t{chave_cifrada_b64}"
            full_data = self.HMAC(data)
            await self.send_message(full_data)

            verified, response_parts = await self.receive_message()
            if verified and response_parts and "UploadKeySucess" in response_parts[0]:
                print(Back.GREEN + f"Arquivo '{filename}' e chave cifrada enviados com sucesso para o servidor.")
                os.remove(caminho_cifrado)
                os.remove(caminho_chave_cifrada)
                return True
            else:
                print(Back.RED + "Erro ao enviar chave cifrada.")
                return False
        else:
            print(Back.RED + "Erro ao iniciar upload.")
            return False         

#-------------------------------------------------------#
#                         CLIENTE                       #
#                        MENU OWNER                     #
# ------------------------------------------------------# 

    async def manage_file(self, ficheiro_escolhido):
        while True:
            print(f"""
            +---------------------------------------------+
            | MENU OWNER - Ficheiro: {ficheiro_escolhido}
            |---------------------------------------------|
            | 1. Ler conteúdo do ficheiro (READ)          |
            | 2. Adicionar conteúdo ao fim (APPEND)       |
            | 3. Substituir conteúdo (WRITE)              |
            | 4. Partilhar ficheiro com outro utilizador  |
            | 5. Ver permissões de partilha (PERMISSIONS) |
            | 0. Voltar ao menu anterior                  |
            +---------------------------------------------+
            """)
            acao = input("Escolha uma ação: ")
            if acao == "1":
                print(f"[READ] A ler o ficheiro '{ficheiro_escolhido}'...")
                #await self.read_file(ficheiro_escolhido)
            elif acao == "2":
                print(f"[APPEND] A adicionar ao ficheiro '{ficheiro_escolhido}'...")
                #await self.write_file(ficheiro_escolhido, is_append=True)
            elif acao == "3":
                print(f"[WRITE] A substituir o ficheiro '{ficheiro_escolhido}'...") 
                #await self.write_file(ficheiro_escolhido, is_append=False)
            elif acao == "4":
                print(f"[SHARE] A partilhar '{ficheiro_escolhido}' com outro utilizador...")
                await self.share_file(ficheiro_escolhido)
            elif acao == "5":
                print(f"[PERMISSIONS] A ver permissões do ficheiro '{ficheiro_escolhido}'...")
            elif acao == "0":
                return  
            else:
                print("Ação inválida.")

#-------------------------------------------------------#
#                         CLIENTE                       #
#                       PEDIR LISTA                     #
# ------------------------------------------------------#  

    async def list_user_files(self):
        email = self.nome_cliente
        if email not in sessions:
            print(Fore.RED + "Sessão inválida. Faça login novamente.")
            return False
            
        token = sessions[email]
        data = f"ListFiles\t{email}\t{token}"
        full_data = self.HMAC(data)
        
        await self.send_message(full_data)
        verified, response_parts = await self.receive_message()
        #print(Back.CYAN + f"Verificando HMAC: {verified}")
        #print(Back.CYAN + f"Resposta do servidor: {response_parts}")
        
        if verified:
            if (response_parts[0] == "FilesList"):
                files = response_parts[1].split("\t")
                #print(Back.YELLOW + f"Ficheiros recebidos: {files}")
                return files
            else:
                print(Back.RED + "Erro ao receber lista de ficheiros.")
                return None
        else:
            print(Back.RED + "Erro na verificação HMAC.")
            return None

#-------------------------------------------------------#
#                         CLIENTE                       #
#                      OWNER HELPER                     #
# ------------------------------------------------------# 

    async def handle_owner_files(self):
        ficheiros = await self.list_user_files()
        
        if ficheiros is None:
            return
            
        print("\n===== Os teus ficheiros =====")
        for idx, f in enumerate(ficheiros):
            print(f"{idx + 1}. {f}")
        print("\n=============================")
        print("0. Fazer upload de novo ficheiro")
        print("-1. Voltar ao menu anterior")
        print("=============================")
        
        escolha = input("Escolha uma opção: ")
        
        if escolha == "0":
            await self.upload_file(self.nome_cliente, sessions[self.nome_cliente])
        elif escolha == "-1":
            return
        elif escolha.isdigit() and 1 <= int(escolha) <= len(ficheiros):
            idx = int(escolha) - 1
            ficheiro_escolhido = ficheiros[idx]
            #print(f"Ficheiro escolhido: {ficheiro_escolhido}")
            await self.manage_file(ficheiro_escolhido)
        else:
            print(Fore.RED + "Opção inválida.")


#-------------------------------------------------------#
#                         CLIENTE                       #
#                          LOGOUT                       #
# ------------------------------------------------------# 

    async def logout(self):
        email = self.nome_cliente
        if email in sessions:
            data = f"Logout\t{email}"
            full_data = self.HMAC(data)

            await self.send_message(full_data)
            response = (await self.reader.read(max_msg_size)).decode()

            if response == "Logout successful":
                del sessions[email]
                print(Fore.GREEN + "Logout realizado com sucesso.")
            else:
                print(Fore.RED + "Erro ao terminar sessão.")
        else:
            print(Fore.RED + "Sessão não encontrada.")
            
        self.authenticated = False
        return True

#-------------------------------------------------------#
#                         CLIENTE                       #
#                        MAIN MENU                      #
# ------------------------------------------------------# 

    async def main_menu(self):
        while self.authenticated:
            print(Style.BRIGHT + Fore.YELLOW + f"""
            +------------------------------------------------+
            |              CLIENTE ({self.nome_cliente})          |
            |                                                |
            | 1. Ver os meus ficheiros (OWNER)               |
            | 2. Ver os ficheiros partilhados comigo (SHARED)|
            | 3. Logout                                      |
            +------------------------------------------------+
            """)
            opcao = input("Escolha uma opção: ")
            
            if opcao == "1":
                await self.handle_owner_files()
            elif opcao == "2":
                await self.handle_shared_files()
            elif opcao == "3":
                await self.logout()
                break
            else:
                print("Opção inválida.")

#-------------------------------------------------------#
#                         CLIENTE                       #
#                      CLOSE CONNECTION                 #
# ------------------------------------------------------# 

    async def close_connection(self):
        self.writer.write(b'\n')
        print('Socket closed!')
        self.writer.close()
        await self.writer.wait_closed()

#-------------------------------------------------------#
#                         CLIENTE                       #
#                        REGISTRO                       #
# ------------------------------------------------------# 

    async def process_registration(self):
        print(Style.BRIGHT + Fore.YELLOW + """
        +------------------------------------------------+
        |                   CLIENTE                      |
        |                                                |
        | Dados a fornecer para efetuar o registo:       |
        +------------------------------------------------+
        """)
        nome = input("Nome: ")
        password = input("Password: ")
        email = input("Email: ")
        
        #validate = self.validate(password, email) # Descomentar para validar
        validate = True
        
        if validate:
            print(Fore.GREEN + "Dados válidos")
            cifra_rsa = rsa.carregar_chave_publica()
            password_enc = cifra_rsa.encrypt(password.encode())
            password_cifrada = base64.b64encode(password_enc).decode()
            
            data = f"Register\t{nome}\t{password_cifrada}\t{email}"
            return self.HMAC(data)
        return "0".encode()
    
#-------------------------------------------------------#
#                         CLIENTE                       #
#                     LOGIN REQUEST                     #
# ------------------------------------------------------# 

    async def process_login_request(self):
        print(Style.BRIGHT + Fore.YELLOW + """
        +------------------------------------------------+
        |                   CLIENTE                      |
        |                                                |
        | Dados a fornecer para efetuar o login:         |
        +------------------------------------------------+
        """)
        email = input("Email: ")
        password = input("Password: ")

        # validate = self.validate(password, email) # Descomentar para validar
        validate = True
        if validate:
            print(Fore.GREEN + "Dados válidos")
            data = "LoginRequest" + "\t" + email
            return self.HMAC(data)
        return "0".encode()
    
#-------------------------------------------------------#
#                         CLIENTE                       #
#                    LOGIN CONFIRMATION                 #
# ------------------------------------------------------# 

    async def process_login_confirmation(self, nonce):
        print("""
        +------------------------------------------------+
        |                   CLIENTE                      |
        |                                                |
        | Forncecer os dados de login (2 vez):           |
        +------------------------------------------------+
        """)
        email = input("Email: ")
        password = input("Password: ")

        cifra_rsa = rsa.carregar_chave_publica()
        password_enc = cifra_rsa.encrypt(password.encode())
        password_cifrada = base64.b64encode(password_enc).decode()

        data_to_create_hmac = password_cifrada + nonce
        client_hmac = hhs.create_hmac_signature(data_to_create_hmac, HMAC_KEY)

        data = f"Login\t{password_cifrada}\t{email}\t{client_hmac}"
        return self.HMAC(data)

#-------------------------------------------------------#
#                         REGISTO                       #
#                         E LOGIN                       #
# ------------------------------------------------------#     


    async def handle_authentication(self):
        nonce = None
        choice = None
        while not self.authenticated:
            if choice != "4":
                print(Style.BRIGHT + Fore.YELLOW + """
                +------------------------------------------------+
                |                   CLIENTE                      |
                |                                                |
                | 1. Registar                                    |
                | 2. Login                                       |
                | 3. Sair                                        |
                +------------------------------------------------+
                """)
                choice = input("Escolha uma opção: ")
            
            if choice == "3":
                return False 
                
            if choice == "1": 
                msg = await self.process_registration()
            elif choice == "2": 
                msg = await self.process_login_request()
            elif choice == "4": 
                msg = await self.process_login_confirmation(nonce)
            else:
                print(Fore.RED + "Opção inválida")
                continue
                
            if msg != "0".encode():
                await self.send_message(msg)
                verified, response_parts = await self.receive_message()
                
                if verified and response_parts:
                    action = response_parts[0]
                    
                    if action == "RegisterSucess":
                        response = response_parts[1].split("\t")
                        print(Fore.GREEN + "Registo feito com sucesso")
                        #generate par de chaves unicas por utilizador
                        caminho_to_save_keys = os.path.join("DB_USER", response[1], "keys")
                        #print (Fore.GREEN + f"Chaves RSA geradas e salvas em: {caminho_to_save_keys}")
                        up.gerar_chaves_rsa(caminho_to_save_keys)
                        
                    elif action == "LoginRequestSucess":
                        print(Fore.GREEN + "Login Request feito com sucesso")
                        #print(Fore.GREEN + "Nonce gerado com sucesso")
                        #print(Fore.GREEN + "nonce: " + response_parts[1])
                        choice = "4"  # Próxima ação: confirmar login com nonce
                        nonce = response_parts[1]
                        
                    elif action == "LoginSucess":
                        login_info = response_parts[1].split("\t")
                        print(Fore.GREEN + "Login feito com sucesso")
                        #print(Fore.GREEN + login_info[0])
                        #print(Fore.GREEN + login_info[1])
                        
                        self.nome_cliente = login_info[0]
                        sessions[self.nome_cliente] = login_info[1]
                        self.authenticated = True
                        return True
        
        return False


#-------------------------------------------------------#
#                         CLIENTE                       #
#                         MAIN LOOP                    #
# ------------------------------------------------------#

async def tcp_echo_client():
    client = Client()
    
    try:
        await client.connect()
        
        success = await client.handle_authentication()
        
        if success and client.authenticated:
            await client.main_menu()
            
    except Exception as e:
        print(f"Erro no cliente: {e}")
    finally:
        await client.close_connection()

def run_client():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client())

run_client()