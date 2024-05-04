#!/usr/bin/env python
# coding: utf-8

# In[1]:


import rsa
import socket
import pickle
import random
from Crypto.Cipher import AES

def main():
    b = int(input("Enter the index of the message you want (0 or 1): "))
    print()
    k = random.randint(0,1000)
    
    client_socket = socket.socket()         
    port = 12345               
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
    for i in range(2):
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
    
    print("Attempting to access the other message using m_{1-b}'.")
    # Trying to access the other message using m_{1-b}'.
    aes_key_enc_oth = m_[1-b]
    aes_key_int_oth = (int.from_bytes(aes_key_enc_oth, byteorder='big') - k) % N
    aes_key_oth = aes_key_int_oth.to_bytes((aes_key_int_oth.bit_length() + 7) // 8, byteorder='big')
    aes_key_oth = aes_key_oth.ljust(16, b'\0')  # Pad key to 16 bytes if necessary
    
    # Attempt to decrypt the non-chosen message for demonstration
    other_b = 1 - b
    nonce, tag, ciphertext = encrypted_data[other_b]
    # Create a new Cipher object for the non-chosen message
    try:
        new_cipher = AES.new(aes_key_oth, AES.MODE_EAX, nonce=nonce)
        data = new_cipher.decrypt_and_verify(ciphertext, tag)
        print(f"Decrypted content of message {other_b}: ", data.decode())
        print("Warning: Decryption of the non-chosen message should not have succeeded.")
    except ValueError:
        print("Expected failure: Decryption failed or MAC check failed for the non-chosen message.")
   
    print()
    print("Closing connection")
    client_socket.close()

main()


# In[ ]:




