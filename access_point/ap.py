import random
from pwn import *


# RC4 functionality
class RC4:
    def __init__(self, key):
        self.key = key


    # gerate S-Box as the identity permutation
    def init_s(self):
        return list(range(256))


    # swap two values in the S-Box by index
    def swap_by_index(self, S, i, j):
        temp = S[i]
        S[i] = S[j]
        S[j] = temp


    # key scheduling algorithm - KSA
    def ksa(self, iv):
        S = self.init_s()
        j = 0
        session_key = iv + self.key
        for i in range(256):
            j = (j + S[i] + session_key[i % len(self.key)]) % 256
            self.swap_by_index(S, i, j)

        return S


    # pseudorandom generation algorithm - PRGA
    def prga(self, S, length):
        i = 0
        j = 0
        keystream = []
        for _ in range(length):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            t = (S[i] + S[j]) % 256
            keystream.append(S[t])

        return keystream


    # encrypt a given plaintext
    def encrypt(self, iv, plaintext):
        S = self.ksa(iv)
        keystream = self.prga(S, len(plaintext))

        # keystream generated should be the same length as the plaintext
        assert len(plaintext) == len(keystream)

        # return the keystream for decryption
        return keystream, [x ^ y for x, y in zip(keystream, list(plaintext))]


    # decrypt a given ciphertext
    def decrypt(self, ciphertext, keystream):
        assert len(ciphertext) == len(keystream)
        return [x ^ y for x, y in zip(keystream, ciphertext)]


# RC4 server driver code
class Server:
    def __init__(self, host, port, key):
        self.host = host
        self.port = port
        self.key = list(key) # converts key bytes to list of ints
        self.snap_hdr = b"\xAA"

    
    # generate a random message and encrypt, return ct, iv
    def random_message_iv(self, A, X):
        # choose a random, short, message length
        n = 3
        m = [int.from_bytes(self.snap_hdr, "little")] 

        # generate n random bytes to encrypt
        for _ in range(n):
            m.append(random.choice([i for i in range(1, 255) if i not in [10]))

        # generate a random IV as well of form [b0, b1, b2]
        iv = [A+3, 255, X]

        # encrypt using IV and m
        rc4_handler = RC4(self.key)
        keystream, ct = rc4_handler.encrypt(iv, m)

        return ct, iv



    # start the server
    def start_server(self):
        listener = listen(4444)
        server = listener.wait_for_connection()
        server.sendline(b"Welcome to the RC4 Oracle")
        
        # server receives first, then sends message back
        for A in range(len(self.key)):
            for X in range(256):
                # skip edge case where X == 10 causes an extra newline when sending bytes
                if X == 10:
                    continue
                ct, iv = self.random_message_iv(A, X)
                client_ct = server.recvline()
                log.info(f"Received {client_ct} from client")
                server.sendline(bytearray(iv + ct))
    
        # clean up
        server.close()
        listener.close()


# main function
def main():
    host = "172.20.0.3"
    port = 4444
    key = b"KEY123"
    # server driver code - starting and listening
    server = Server(host, port, key)
    server.start_server()


if __name__ == '__main__':
    main()







