import logging
import socket
import struct
import select
import threading
from aes import AesCrypt

KEYFILE = 'key.txt'
# ip = 0
ip = "127.0.0.1"
port = 2026
# port= 0

def send_data(sock, data):
    # print(data)
    bytes_sent = 0
    while True:
        r = sock.send(data[bytes_sent:])
        # 如果设置为nonblock，send()返回值-1，立即返回
        if r<0:
            return r
        bytes_sent += r
        #全部接收
        if bytes_sent == len(data):
            return bytes_sent

#转发请求
def handle_tcp(sock, server):
    try:
        fdset = [sock, server]
        while True:
            #IO多路复用select监听套接字是否有数据
            #三个参数：被触发的套接字， 监控和接收的所有要发出去的data， 监控错误信息
            r, w, e = select.select(fdset, [], [])
            if sock in r:
                data = sock.recv(4096)

                if len(data) <= 0:
                    break
                result = send_data(server, data)
                if result < len(data):
                    raise Exception('failed to send all data')

            if server in r:
                data = server.recv(4096)
                if len(data) <= 0:
                    break
                result = send_data(sock, data)
                if result < len(data):
                    raise Exception('failed to send all data')

    except Exception as e:
        raise(e)
    finally:
        sock.close()
        server.close()

#接收浏览器请求，socket5连接认证
def handle_con(sock, addr, ac):
    req = sock.recv(256)
    sock.send(b"\x05\x00")
    data = sock.recv(4) or '\x00' * 4
    print("debug data:", data)
    mode = data[1]
    if mode != 1:
        return
    iv = ac.iv
    print('iv:', iv)
    print('key:', ac.key)
    info = iv
    addr_type = data[3]
    if addr_type == 1:
        addr_ip = sock.recv(4)
        info += b"\x01" + addr_ip
    elif addr_type == 3:
        add_len = sock.recv(1)
        info += b"\x03"
        addr_len = int.from_bytes(add_len, byteorder='big')
        addr = sock.recv(addr_len)
        addr_dns = ac.encrypt(addr)
        print('addr:', addr)
        print('addr_dns:', addr_dns)
        addr_len = len(addr_dns).to_bytes(1, byteorder='big')
        print('debug len:', addr_len)
        info += addr_len + addr_dns
    elif addr_type == 4:
        addr_ip = sock.recv(16)
        info += b"\x04" + addr_ip
    else:
        return
    remote_addr_port = sock.recv(2)
    info += remote_addr_port

    reply = b"\x05\x00\x00\x01"
    reply += socket.inet_aton('192.168.43.34') + struct.pack(">H", 8888)
    print("debug reply:", reply)
    sock.send(reply)

    try:
        # server = socket.create_connection(("47.242.111.107", 19999))
        server = socket.create_connection((ip, port))
        print(port)
        print("debug connection: connect with the server...")
    except socket.error as e:
        logging.error(e)
        return
    print("debug info:", info)
    server.send(info)
    handle_tcp(sock, server)
class Client:
    def aaa(p1,p2):
        ip = p1
        port = p2
        print(ip,port)
        with open(KEYFILE, 'r') as f:
            key = f.read()
        ac = AesCrypt(key)
        socketServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socketServer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        socketServer.bind(('', 2022))
        socketServer.listen(5)

        try:
            while True:
                # 监听本地浏览器
                sock, addr = socketServer.accept()
                t = threading.Thread(target=handle_con, args=(sock, addr, ac))
                t.start()
        except socket.error as e:
            logging.error(e)
        except KeyboardInterrupt:
            socketServer.close()

# if __name__ == '__main__':
#     Client.aaa("127.0.0.1", 2026)


# class Client:
#     pass