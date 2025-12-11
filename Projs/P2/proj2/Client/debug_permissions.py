
import json
import os
import sys

def debug_permissions(owner_email, user_email, file_path):
    """
    Debug script to check permissions for a specific file
    """
    permissions_path = os.path.join("..", "WebAPI", "DB", owner_email, "OWNER", "permissions.json")
    
    if not os.path.exists(permissions_path):
        print(f"Erro: Arquivo de permissões não encontrado em {permissions_path}")
        return
    
    try:
        with open(permissions_path, 'r') as f:
            permissions = json.load(f)
            
        print(f"=== Verificando permissões para {file_path} ===")
        print(f"Usuário: {user_email}")
        print(f"Owner: {owner_email}")
        
        # Verificar se há uma entrada exata para o arquivo
        if file_path in permissions:
            file_perms = permissions[file_path].get(user_email)
            print(f"\nPermissões exatas para '{file_path}':")
            print(f"  => {file_perms}")
        else:
            print(f"\nNenhuma permissão exata encontrada para '{file_path}'")
            
        # Procurar variações do caminho
        print("\nProcurando por variações do caminho:")
        for perm_path in permissions:
            if perm_path.startswith(file_path) or file_path.startswith(perm_path):
                user_perms = permissions[perm_path].get(user_email)
                print(f"  - '{perm_path}': {user_perms}")
                
        # Se for um arquivo .metadata, verificar a pasta pai
        if file_path.endswith("/.metadata"):
            folder_path = file_path[:-10]  # Remove "/.metadata"
            print(f"\nVerificando permissões para pasta pai '{folder_path}':")
            if folder_path in permissions:
                folder_perms = permissions[folder_path].get(user_email)
                print(f"  => {folder_perms}")
            else:
                print(f"  => Nenhuma permissão encontrada")
                
        print("\nTodas as permissões disponíveis para este usuário:")
        for path, users in permissions.items():
            if user_email in users:
                print(f"  - '{path}': {users[user_email]}")
                
    except Exception as e:
        print(f"Erro ao processar permissões: {str(e)}")
        
if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Uso: python debug_permissions.py <owner_email> <user_email> <file_path>")
        print("Exemplo: python debug_permissions.py martim@example.com joao@example.com pasta_de_pastas_to_send/.metadata")
        sys.exit(1)
        
    owner_email = sys.argv[1]
    user_email = sys.argv[2]
    file_path = sys.argv[3]
    
    debug_permissions(owner_email, user_email, file_path)