#!/usr/bin/env python
# coding: utf-8

import rsa       # For access to RSA algorithm
import socket    # For socket interaction
import pickle    # For sending arrays across  
import random    # For pseudo-random number generation

# Server Setup
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
port = 12345
(pubkey, privkey) = rsa.newkeys(512)
d = privkey.d
N = pubkey.n
saved = pubkey.save_pkcs1(format='DER')
s.bind(('', port))
s.listen(5)

# Input for messages
num_messages = int(input("Enter the number of messages: "))
messages = [int(input(f"Enter message {i+1}: ")) for i in range(num_messages)]
rand_msg = [random.randint(1, 100) for _ in range(num_messages)]

# Modular Exponentiation
def mod_exp(k, e, N):
    if e == 0:
        return 1
    ans = mod_exp(k, e//2, N) % N
    ans = (ans * ans) % N
    if e % 2 == 1:
        ans = (ans * k) % N
    return ans

# Client Server Interaction
def main():
    c, addr = s.accept()
    print("Connection Established. Sending public key.")
    c.send(saved)
    print("Sending random messages ", rand_msg)
    c.send(pickle.dumps(rand_msg))

    print("Received v")
    v = int(c.recv(1024).decode())

    k = [mod_exp(v - i, d, N) for i in rand_msg]  # Computing k_i

    m_ = [messages[i] + k[i] for i in range(len(messages))]  # Computing m'

    print("Sending m' = ", m_)
    c.send(pickle.dumps(m_))

    print("Closing connection")
    c.close()

main()
