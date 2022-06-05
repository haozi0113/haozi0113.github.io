import logging
import socket
import struct
import select
import threading
from Crypto.Cipher import AES
from  Crypto import Random

AESBLOCKSIZE = 16
KEYFILE = 'key.txt'
port = 2026

class AesCrypt(object):

    def __init__(self, key):
        self.key = key.encode('utf-8')
        self.mode = AES.MODE_CBC
        self.iv = Random.new().read(AES.block_size)

    # 加密函数，如果text不足16位就用空格补足为16位，
    # 如果大于16当时不是16的倍数，那就补足为16的倍数。
    def encrypt(self, text):
        if(type(text) == str): text = text.encode()
        cryptor = AES.new(self.key, self.mode,self.iv)
        # 这里密钥key 长度必须为16（AES-128）,
        # 24（AES-192）,或者32 （AES-256）Bytes 长度
        # 目前AES-128 足够目前使用
        length = 16
        count = len(text)
        if count < length:
            add = (length - count)
            # \0 backspace
            # text = text + ('\0' * add)
            text = text + ('\0' * add).encode('utf-8')
        elif count > length:
            add = (length - (count % length))
            # text = text + ('\0' * add)
            text = text + ('\0' * add).encode('utf-8')
        self.ciphertext = cryptor.encrypt(text)
        # 因为AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
        # 所以这里统一把加密后的字符串转化为16进制字符串
        return self.ciphertext

    # 解密后，去掉补足的空格用strip() 去掉
    def decrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.iv)
        plain_text = cryptor.decrypt(text)
        # return plain_text
        return plain_text.rstrip(b'\0')


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
def handle_tcp(sock, remote):
    try:
        fdset = [sock, remote]
        while True:
            r, w, e = select.select(fdset, [], [])
            if sock in r:
                data = sock.recv(4096)
                print(data)
                if len(data) <= 0:
                    break
                result = send_data(remote, data)
                if result < len(data):
                    raise Exception('failed to send all data')

            if remote in r:
                data = remote.recv(4096)
                if len(data) <= 0:
                    break
                result = send_data(sock, data)
                if result < len(data):
                    raise Exception('failed to send all data')

    except Exception as e:
        raise(e)
    finally:
        sock.close()
        remote.close()

def handle_con(sock, addr):
    with open(KEYFILE, 'r') as f:
        key = f.read()
    ac = AesCrypt(key)
    ac.iv = sock.recv(AESBLOCKSIZE)
    print('iv:', ac.iv)
    addr_type = sock.recv(1) or '\x00'
    addr_type = int.from_bytes(addr_type, byteorder='big')
    print("debug addr_type:", addr_type)
    if addr_type == 1:
        addr_ip = sock.recv(4)
        remote_addr = socket.inet_ntoa(addr_ip)
    elif addr_type == 3:
        addr_len = int.from_bytes(sock.recv(1), byteorder='big')
        addr = sock.recv(addr_len)
        print("addr:", addr)
        remote_addr = ac.decrypt(addr)
        print("remote_addr:", remote_addr)
    elif addr_type == 4:
        addr_ip = sock.recv(16)
        remote_addr = socket.inet_ntop(socket.AF_INET6, addr_ip)
    else:
        print("exit")
        return
    remote_addr_port = struct.unpack('>H', sock.recv(2))

    try:
        print("remote:", remote_addr, ",", remote_addr_port )
        remote = socket.create_connection((remote_addr, remote_addr_port[0]))
        logging.info('connecting %s:%d' % (remote_addr, remote_addr_port[0]))
    except socket.error as e:
        logging.error(e)
        return

    handle_tcp(sock, remote)

def main():
    # socks.set_default_proxy(socks.SOCKS5, "localhost", 1080)
    # socket.socket = socks.socksocket
    socketServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socketServer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socketServer.bind(('', port))
    socketServer.listen(5)

    try:
        while True:
            sock, addr = socketServer.accept()
            t = threading.Thread(target=handle_con, args=(sock, addr))
            t.start()
    except socket.error as e:
        logging.error(e)
    except KeyboardInterrupt:
        socketServer.close()

if __name__ == '__main__':
    main()