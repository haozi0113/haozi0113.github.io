import logging
import socket
import struct
import select
import threading

def send_data(sock, data):
    print(data)
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
            #IO多路复用select监听套接字是否有数据
            #三个参数：被触发的套接字， 监控和接收的所有要发出去的data， 监控错误信息
            r, w, e = select.select(fdset, [], [])
            if sock in r:
                data = sock.recv(4096)

# ----------------------------------------------------------------------------------------insert here！
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

#接收客户端请求，socket5连接认证
def handle_con(sock, addr):
    sock.recv(256)
    #无需进一步认证信息
    sock.send(b"\x05\x00")
    data = sock.recv(4) or '\x00' * 4
    #取出CMD
    mode = data[1]
    # CMD为0x01表示CONNECT继续
    if mode != 1:
        return
    #取出ATYE字段
    addr_type = data[3]
    if addr_type == 1:
        addr_ip = sock.recv(4)
        #socket.inet_ntoa(ip_string)转换IPV4地址字符串成为32位打包的二进制格式（长度为4个字节的二进制字符串），它不支持IPV6
        remote_addr = socket.inet_ntoa(addr_ip)
    elif addr_type == 3:
        #byteorder='big':大端存储
        addr_len = int.from_bytes(sock.recv(1), byteorder='big')
        remote_addr = sock.recv(addr_len)
    elif addr_type == 4:
        addr_ip = sock.recv(16)
        #socket.inet_pton(address_family,ip_string)转换IP地址字符串为打包二进制格式
        # 地址家族为AF_INET和AF_INET6，它们分别表示IPV4和IPV6。
        remote_addr = socket.inet_ntop(socket.AF_INET6, addr_ip)
    else:
        return
    #>H：大端2字节无符号整数
    remote_addr_port = struct.unpack('>H', sock.recv(2))

    #返回给客户端success
    reply = b"\x05\x00\x00\x01"
    reply += socket.inet_aton('127.0.0.1') + struct.pack(">H", 8888)
    sock.send(reply)

    #拿到remote address信息后建立连接
    try:
        remote = socket.create_connection((remote_addr, remote_addr_port[0]))
        logging.info('connecting %s:%d' % (remote_addr, remote_addr_port[0]))
    except socket.error as e:
        logging.error(e)
        return

    handle_tcp(sock, remote)

def main():
    #新建一个服务端套接字，IPV4，流式通信
    socketServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #SOL_SOCKET：被设置的选项的级别，如果想要在套接字级别上设置选项，就必须把level设置为SOL_SOCKET
    socketServer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    socketServer.bind(('', 2022))
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