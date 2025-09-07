from pwn import *


# attacker functionality
class Attacker:
    def __init__(self, data):
        # list of IVs and CT[0] values
        self.data = data 
        self.snap_hdr = b"\xAA"


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
        init_1 = 0
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
        formatted = "".join([chr(int.from_bytes(b, "little")) for b in temp])
        log.info(f"Recovered secret key {formatted}")


    # recover the secret key
    def recover_key(self):
        key_len = 6
        session_key = [0] * 3
        # iterate A to the number of bytes we need to recover
        for A in range(key_len):
            print(f"Iteration: {A}")
            prob_table = [0] * 256 # probabaility table for every key byte recovery
            # iterate over every IV, c[0] gathered
            for row in self.data:
                # avoid any corrupted data
                if len(row) != 4:
                    continue
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
                    ks_byte = int(row[3]) ^ int.from_bytes(self.snap_hdr, "little") # ct[0] ^ 0xAA
                    # S not completely known when server runs PRGA, bias is no swap of S[0] or S[1] in KSA
                    # ~5% chance S[0] and S[1] never get swapped, allowing inversion of PRGA
                    key_byte = (ks_byte - j - S[A+3]) % 256 # inversion of the PRGA
                    prob_table[key_byte] += 1 # each byte has a frequency counter, increment if resolved condition met
            # get the byte with the highest probability counter - after all IVs have been iterated     
            session_key.append(prob_table.index(max(prob_table)))         
            log.info(f"Recovered key byte: {prob_table.index(max(prob_table))}")
        # format recovered key, remove IV from beginning
        self.format_key(session_key)


# utils class for traffic proxying
class Utils:
    def __init__(self, hosts):
        self.proxy = hosts["attacker"]
        self.ap = hosts["access_point"]
        self.client = hosts["client"]
        self.data = [] # only need iv and ct[0] stored
    

    # connect to the access point and receive welcome banner
    def connect_to_ap(self, client_sock):
        # make a socket to connect to the AP
        ap_io = remote(self.ap[0], self.ap[1])
        client_sock.send(ap_io.recvline())

        return ap_io


    # add [iv[0], iv[1], iv[2], ct[0]] to the dataset
    def add_to_dataset(self, ct):
        iv = ct[:3]
        ct_0 = ct[3:4]
        self.data.append(list(iv + ct_0))



    # target function for the thread(s) that handles a connection
    def handle_connection(self, client_io):
        ap_io = self.connect_to_ap(client_io)

        # now we are ready to intercept back and forth messaging
        while True:
            try:
                client_msg = client_io.recvline()
                ap_io.send(client_msg)
                ap_msg = ap_io.recvline()
                client_io.send(ap_msg)
                # log the data
                self.add_to_dataset(client_msg)
                self.add_to_dataset(ap_msg)

            # stop data collection when client and ap stop sending
            except EOFError as e:
                break
        
        ap_io.close()


    # start the proxy socket
    def start_proxy(self):
        listener = listen(self.proxy[1])

        # accept connection
        client_io = listener.wait_for_connection()
        # populate the dataset by intercepting ciphertext and IVs
        self.handle_connection(client_io)
        client_io.close()


# main function
def main():
    # if you change the docker networking, change these values
    hosts = {"attacker" : ["172.20.0.3", 4444], "access_point" : ["172.20.0.2", 4444], "client" : ["172.20.0.4", 4444]}
    utils = Utils(hosts)
    utils.start_proxy()
    attacker = Attacker(utils.data)
    print(attacker.data)
    attacker.recover_key()



if __name__ == '__main__':
    main()
