import asyncio
import ssl

conn_port = 8443
max_msg_size = 9999

class Client:
    """ Classe que implementa a funcionalidade de um CLIENTE. """
    def __init__(self, sckt=None):
        self.sckt = sckt
        self.msg_cnt = 0
    def process(self, msg=b""):
        self.msg_cnt += 1
        print('Received (%d): %r' % (self.msg_cnt, msg.decode()))
        print('Input message to send (empty to finish)')
        new_msg = input().encode()
        return new_msg if len(new_msg)>0 else None

async def tcp_echo_client():

    #TAL COMO NO SERVIDOR, TAMBÉM AQUI TEMOS QUE CRIAR UM CONTEXTO SSL PARA O CLIENTE
    client_ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT) # Criar um contexto para o cliente
    client_ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3  # Forçar TLS 1.3
    
    client_ssl_ctx.load_verify_locations("ca.crt") # carregar o certificado da CA
    
    client_ssl_ctx.check_hostname = False # Não verificar o hostname, pois estamos a usar um certificado auto-assinado
    client_ssl_ctx.verify_mode = ssl.CERT_REQUIRED # Forçar a verificação do certificado

    reader, writer = await asyncio.open_connection('127.0.0.1', conn_port, ssl=client_ssl_ctx)
    
    # A PARTIR DAQUI O CÓDIGO É IGUAL AO DO CLIENTE SEM TLS (SEM MUDANÇAS EXTRAS)
    addr = writer.get_extra_info('peername')
    client = Client(addr)
    msg = client.process()
    while msg:
        writer.write(msg)
        msg = await reader.read(max_msg_size)
        if msg:
            msg = client.process(msg)
        else:
            break
    writer.write(b'\n')
    print('Socket closed!')
    writer.close()

def run_client():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client())

run_client()
