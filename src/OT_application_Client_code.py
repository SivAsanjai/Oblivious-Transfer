#!/usr/bin/env python
# coding: utf-8

# In[5]:


import rsa
import socket
import pickle
import random
from Crypto.Cipher import AES
import urllib

def main():
    b = int(input("Enter the index of the message you want (0 for Believer, 1 for Cupid, 2 for Baby, 3 for Love Story, 4 for Bad Blood): "))
    print()
    k = random.randint(0,1000)
    
    client_socket = socket.socket()         
    port = 22552             
    client_socket.connect(('127.0.0.1', port))
    print("Connection Established")
    print()
    
    print("Recieving RSA Public key.")
    print()
    saved_key = client_socket.recv(1024)
    key = rsa.PublicKey.load_pkcs1(saved_key, format='DER')
    N, e = (key.n, key.e)
    
    x = pickle.loads(client_socket.recv(1024))
    print("Receiving random messages")
    print()
    
    v = (x[b] + pow(k, e, N)) % N
    client_socket.send(f"{v}".encode())
    print("Sending v = ", v)
    print()
    
    print("Recieving m' and using m_b'.")
    print()
    m_ = pickle.loads(client_socket.recv(1024))
    aes_key_enc = m_[b]
    aes_key_int = (int.from_bytes(aes_key_enc, byteorder='big') - k) % N
    aes_key = aes_key_int.to_bytes((aes_key_int.bit_length() + 7) // 8, byteorder='big')
    aes_key = aes_key.ljust(16, b'\0')  # Pad key to 16 bytes if necessary
    
    print("Receiving encrypted messages.")
    encrypted_data = []
    # Store all encrypted message components
    for i in range(5):
        nonce = client_socket.recv(16)
        tag = client_socket.recv(16)
        ciphertext = client_socket.recv(1024)
        encrypted_data.append((nonce, tag, ciphertext))
    
    # Decrypt only the chosen message
    nonce, tag, ciphertext = encrypted_data[b]
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    print(f"Decrypted content of message {b}: ", data.decode())
    print()
    urllib.urlopen(data.decode())
    
    print("Closing connection")
    client_socket.close()

main()


# In[ ]:




