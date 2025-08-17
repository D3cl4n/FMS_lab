from pwn import *


# RC4 functionality
class RC4:
    def __init__(self, key):
        self.key = key


    # generate S-Box as the identity permutation
    def init_s(self):
        return list(range(256))


    # swap two values in the S-Box by index
    def swap_by_index(self, S, i, j):
        temp = S[i]
        S[i] = S[j]
        S[j] = temp


    # key schedling algorithm - KSA
    def ksa(self, iv):
        S = self.init_s()
        session_key = iv + self.key
        j = 0
        for i in range(256):
            j = (j + S[i] + session_key[i % len(session_key)]) % 256
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
            t = (S[i] + S[i] ) % 256
            keystream.append(S[t])

        return keystream


    # encrypt a given plaintext
    def encrypt(self, iv, plaintext):
        iv_ints = [int(b) for b in iv]
        S = self.ksa(iv_ints)
        keystream = self.prga(S, len(plaintext))
        
        # keystream generated should be the same length as the plaintext
        assert len(plaintext) == len(keystream)

        # return the keystream for decryption
        return keystream, [x ^ y for x, y in zip(keystream, plaintext)]


    # decrypt a given ciphertext
    def decrypt(self, ciphertext, keystream):
        assert len(ciphertext) == len(keystream)
        return [x ^ y for x, y in zip(keystream, ciphertext)]



# RC4 server driver code
class Server:
    def __init__(self, host, port, key):
        self.host = host
        self.port = port
        self.key = key

    # convert key to ints
    def key_format(self):
        key_temp = []
        for i in range(0, len(self.key), 2):
            key_temp.append(int(self.key[i:i+2], 16))

        return key_temp

    # start the server
    def start_server(self):
        listener = listen(4444)
        server = listener.wait_for_connection()
        server.sendline(b"Welcome to the RC4 Oracle")

        # clean up
        server.close()
        listener.close()

