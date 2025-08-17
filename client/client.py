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
    ap_addr = "" # TODO: CHANGE ME
    


if __name__ == '__main__':
    main()
