import asyncio
import ssl

conn_cnt = 0
conn_port = 8443
max_msg_size = 9999

class ServerWorker(object):
    def __init__(self, cnt, addr=None):
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0

    def process(self, msg):
        self.msg_cnt += 1
        txt = msg.decode()

        print('%d : %r' % (self.id, txt))

        new_msg = txt.upper().encode()
        if len(new_msg) <= 0:
            new_msg = None

        print ('%d : Processing %r' % (self.id, new_msg))

        return new_msg

async def handle_echo(reader, writer):
    global conn_cnt
    conn_cnt += 1
    addr = writer.get_extra_info('peername')
    srvwrk = ServerWorker(conn_cnt, addr)

    data = await reader.read(max_msg_size)
    while True:
        if not data:
            continue
        if data[:1] == b'\n':
            break
        data = srvwrk.process(data)
        if not data:
            break
        writer.write(data)
        await writer.drain()
        data = await reader.read(max_msg_size)
    print("[%d]" % srvwrk.id)
    writer.close()

def run_server():
    loop = asyncio.new_event_loop()

    #ESTA PARTE TEVE QUE MUDAR PORQUE PRECISAMOS DE IMPLEMENTAR O TLS
    
    server_ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER) # Criar um contexto para o servidor
    server_ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3  # Forçar TLS 1.3
    
    server_ssl_ctx.load_cert_chain(certfile="server.crt", keyfile="server.key") # carrergar o certificado e a chave privada


    coro = asyncio.start_server(handle_echo, '127.0.0.1', conn_port, ssl=server_ssl_ctx) # aqui é onde se passa o contexto SSL

    #TUDO IGUAL A PARTIR DAQUI
    server = loop.run_until_complete(coro)

    print('Serving on {}'.format(server.sockets[0].getsockname()))
    print('  (type ^C to finish)\n')

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
    print('\nFINISHED!')

run_server()
