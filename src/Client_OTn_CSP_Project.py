#!/usr/bin/env python
# coding: utf-8

import rsa       # For access to RSA algorithm
import socket    # For socket interaction
import pickle    # For sending arrays across  
import random    # For pseudo-random number generation

# Client Setup
s = socket.socket()         
port = 12345               
s.connect(('127.0.0.1', port)) 
print("Connection Established")

# Modular Exponentiation
def mod_exp(k, e, N):
    if e == 0:
        return 1
    ans = mod_exp(k, e//2, N) % N
    ans = (ans * ans) % N
    if e % 2 == 1:
        ans = (ans * k) % N
    return ans

def main():
    saved_key = s.recv(1024)
    print("Received public key")
    key = rsa.key.PublicKey.load_pkcs1(saved_key, format='DER')
    N, e = (key.n, key.e)
    
    x = s.recv(1024)
    x = pickle.loads(x)
    num_messages = len(x)
    print("Received random messages")
    
    b = int(input(f"Enter the index of the message you want (0 to {num_messages-1}): "))  # The index of the message the client wants
    k = random.randint(0, 1000)  # Random number
    
    v = (x[b] + mod_exp(k, e, N)) % N
    s.send(f"{v}".encode())
    print("Sending v")
    
    m_ = s.recv(1024)
    m_ = pickle.loads(m_)
    m = (m_[b] - k) % N
    print("Requested message: ", m)
    
    print("Closing connection")
    s.close() 

main()
