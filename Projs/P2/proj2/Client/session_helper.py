from PathsImports import *
from register_helper import *

def get_machine_id():
    hostname = socket.gethostname()
    username = getpass.getuser()
    return f"{hostname}_{username}"

def get_or_create_terminal_number():
    os.makedirs(TERMINAL_BASE_DIR, exist_ok=True)

    term_num_file = os.path.join(TERMINAL_BASE_DIR, "terminal_number.txt")
    
    if not os.path.exists(term_num_file):
        print("\n" + "="*50)
        print("PRIMEIRA EXECUÇÃO DETECTADA")
        print("="*50)
        print("Digite o número deste terminal (ex: 1, 2, 3...)")
        print("Use um número diferente para cada terminal físico/janela que você utilizar")
        terminal_number = input("Número do terminal: ").strip()
        
        with open(term_num_file, "w") as f:
            f.write(terminal_number)
        
        return terminal_number
    else:
        with open(term_num_file, "r") as f:
            return f.read().strip()

def get_terminal_id():
    machine_id = get_machine_id()
    terminal_number = get_or_create_terminal_number()
    terminal_id = f"{machine_id}_term{terminal_number}"
    
    return terminal_id

def init_sessions_dir():
    os.makedirs(SESSIONS_DIR, exist_ok=True)

def get_active_session(terminal_id=None):
    if terminal_id is None:
        terminal_id = get_terminal_id()
    
    session_file = os.path.join(SESSIONS_DIR, f"session_{terminal_id}.txt")
    
    if not os.path.exists(session_file):
        return None

    try:
        with open(session_file, "r") as f:
            email = f.read().strip()
            token_path = get_token_path(email)
            if not os.path.exists(token_path):
                return None
            return email
    except Exception:
        return None

def set_active_session(email, terminal_id=None):
    if terminal_id is None:
        terminal_id = get_terminal_id()
    
    init_sessions_dir()
    
    session_file = os.path.join(SESSIONS_DIR, f"session_{terminal_id}.txt")
    
    with open(session_file, "w") as f:
        f.write(email)
    
    typer.echo(f"Sessão ativa definida para {email} (Terminal ID: {terminal_id})")

def clear_active_session(terminal_id=None):
    if terminal_id is None:
        terminal_id = get_terminal_id()
    
    session_file = os.path.join(SESSIONS_DIR, f"session_{terminal_id}.txt")
    
    if os.path.exists(session_file):
        os.remove(session_file)
        typer.echo(f"Sessão encerrada para este terminal (ID: {terminal_id})")

def list_active_sessions():
    if not os.path.exists(SESSIONS_DIR):
        typer.echo("Nenhuma sessão ativa.")
        return
    
    sessions = {}
    for filename in os.listdir(SESSIONS_DIR):
        if filename.startswith("session_") and filename.endswith(".txt"):
            terminal_id = filename[8:-4] 
            with open(os.path.join(SESSIONS_DIR, filename), "r") as f:
                email = f.read().strip()
                sessions[terminal_id] = email
    
    if not sessions:
        typer.echo("Nenhuma sessão ativa.")
        return
    
    current_terminal = get_terminal_id()
    typer.echo("Sessões ativas:")
    for terminal_id, email in sessions.items():
        if terminal_id == current_terminal:
            typer.echo(f"  * {email} (Terminal ID: {terminal_id}) [ESTE TERMINAL]")
        else:
            typer.echo(f"  - {email} (Terminal ID: {terminal_id})")

def verify_active_session(email=None):
    terminal_id = get_terminal_id()
    active_email = get_active_session(terminal_id)

    if active_email is None:
        typer.echo(f"Nenhum utilizador com sessão ativa neste terminal (ID: {terminal_id}). Faça login primeiro.")
        return False

    if email is not None and email != active_email:
        typer.echo(f"Erro: Está a tentar executar uma operação para {email} mas a sessão ativa neste terminal é de {active_email}.")
        typer.echo("Para mudar de utilizador, faça logout e depois login com o utilizador pretendido.")
        return False

    return True