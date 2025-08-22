import time
from pwn import *


# client functionality
class Client:
    def __init__(self, host, port, key):
        self.host = host
        self.port = port
        self.key = key
        self.snap_hdr = b"\xAA"


    # start the client functionality
    def start_client(self):
        io = remote(self.host, self.port)
        welcome = io.recvline()
        log.info(f"Received: {welcome}")
        while True:
            io.sendline(b"test1")
            ct = io.recvline()
            log.info(f"Received {ct} from server")
            break
        


# main function
def main():
    ap_addr = "172.20.0.2" # static IP of the access point
    port = 4444
    key = b"test"
    # client driver code - starting and sending data
    client = Client(ap_addr, port, key)
    client.start_client()


if __name__ == '__main__':
    time.sleep(5)
    main()
