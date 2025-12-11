import time
import threading

class SessionManager:
    def __init__(self, session_timeout=300):  # Tempo de expiração em segundos (5 minutos)
        self.sessions = {}  # Formato: {email: (token, expiration_time)}
        self.session_timeout = session_timeout
        self.lock = threading.Lock()  # Para evitar problemas de concorrência

    def create_session(self, email, token):
        """Cria uma nova sessão para o usuário."""
        expiration_time = time.time() + self.session_timeout
        with self.lock:
            self.sessions[email] = (token, expiration_time)

    def is_authenticated(self, email, token):
        """Verifica se o token do usuário ainda é válido."""
        with self.lock:
            if email in self.sessions:
                stored_token, expiration_time = self.sessions[email]
                if stored_token == token and time.time() < expiration_time:
                    return True
                else:
                    # Se o tempo expirou, remove a sessão
                    if time.time() >= expiration_time:
                        del self.sessions[email]
                    return False
            return False

    def remove_session(self, email):
        """Remove a sessão do usuário (logout)."""
        with self.lock:
            if email in self.sessions:
                del self.sessions[email]
                return True
        return False

    def cleanup_expired_sessions(self):
        """Remove sessões expiradas periodicamente (pode ser executado em uma thread separada)."""
        while True:
            time.sleep(60)  # Limpa a cada minuto
            with self.lock:
                now = time.time()
                self.sessions = {email: (token, exp) for email, (token, exp) in self.sessions.items() if exp > now}

# Criar uma instância global do gerenciador de sessões
session_manager = SessionManager()