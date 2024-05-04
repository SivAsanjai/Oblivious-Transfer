#!/usr/bin/env python
# coding: utf-8

# In[1]:


import rsa
import socket
import pickle
import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return cipher.nonce, ciphertext, tag

def main():
    m0 = input("Enter message 0: ")
    m1 = input("Enter message 1: ")
    print()
    messages = [str(m0), str(m1)]
    aes_keys = [get_random_bytes(16) for _ in range(2)]  # Generate AES keys for messages
    encrypted_messages = [encrypt_message(aes_keys[i], messages[i]) for i in range(2)]
    
    (pubkey, privkey) = rsa.newkeys(512)
    d = privkey.d
    N = pubkey.n
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port = 12345
    server_socket.bind(('', port))
    server_socket.listen(5)
    
    client_socket, addr = server_socket.accept()
    print("Connection Established.")
    print()
    print("Sending RSA public key: ", N)
    print()
    
    saved = pubkey.save_pkcs1(format='DER')
    client_socket.send(saved) 
    
    rand_msg = [random.randint(1,100) for i in range(2)]
    print("Sending random messages ", rand_msg)
    print()
    client_socket.send(pickle.dumps(rand_msg))
    
    print("Recieving v.")
    print()
    v = int(client_socket.recv(1024).decode())
    k = [pow(v - i, d, N) for i in rand_msg]
    
    # Convert AES keys from bytes to integers, perform modular addition, then convert back to bytes
    m_ = []
    for i in range(len(aes_keys)):
        m_i = int.from_bytes(aes_keys[i], byteorder='big')
        m_i_prime = (m_i + k[i]) % N
        m_i_prime_bytes = m_i_prime.to_bytes((m_i_prime.bit_length() + 7) // 8, byteorder='big')
        m_.append(m_i_prime_bytes)

    print("Sending m' = ", m_)
    print()
    client_socket.send(pickle.dumps(m_))
    
    # Send encrypted messages
    print("Sending encrypted messages.")
    print()
    for nonce, ciphertext, tag in encrypted_messages:
        client_socket.send(nonce + tag + ciphertext)
    
    print("Closing connection")
    client_socket.close()

main()


# In[ ]:




