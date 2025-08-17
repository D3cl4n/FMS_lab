from pwn import *


# client functionality
class Client:
    def __init__(self, host, port, key):
        self.host = host
        self.port = port
        self.key = key
        self.io = remote(host, port)


# main function
def main():
    ap_addr = "172.20.0.2" # static IP of the access point
    port = 4444
    client = Client(ap_addr, port, b"test") # TODO: change key
    log.info(client.recvline())
    


if __name__ == '__main__':
    main()
