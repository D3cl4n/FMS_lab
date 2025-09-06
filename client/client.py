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


# client functionality
class Client:
    def __init__(self, host, port, key):
        self.host = host
        self.port = port
        self.key = list(key) # converts key bytes to list of ints
        self.snap_hdr = b"\xAA"


    # convert key to ints
    def key_format(self):
        key_temp = []
        for i in range(0, len(self.key), 2):
            key_temp.append(int(self.key[i:i+2], 16))

        return key_temp


    # generate a random message and encrypt, return ct, iv
    def random_message_iv(self, A, X):
        # choose a random, short, message length
        n = 3
        m = [int.from_bytes(self.snap_hdr, "little")]

        # generate n random bytes to encrypt
        for _ in range(n):
            m.append(random.randint(0, 255))

        # generate weak IV of the form [A+3, N-1, X]
        iv = [A + 3, 255, X]

        # encrypt using IV and m
        rc4_handler = RC4(self.key)
        keystream, ct = rc4_handler.encrypt(iv, m)

        return ct, iv
        

    # start the client functionality
    def start_client(self):
        io = remote(self.host, self.port)
        welcome = io.recvline()
        log.info(f"Received: {welcome}")
    
        # send ciphertexts and weak IVs to access point
        for A in range(len(self.key)):
            for X in range(256):
                ct, iv = self.random_message_iv(A, X)
                io.sendline(bytearray(iv + ct))
                ap_ct = io.recvline()
                log.info(f"Received {ap_ct} from server")
        

# main function
def main():
    ap_addr = "172.20.0.3" # static IP of the attacker, simulating proxy
    port = 4444
    key = b"KEY123"
    # client driver code - starting and sending data
    client = Client(ap_addr, port, key)
    client.start_client()



if __name__ == '__main__':
    main()
