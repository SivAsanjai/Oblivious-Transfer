#!/usr/bin/env python
# coding: utf-8

# In[3]:


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
    m0 = "https://youtu.be/W0DM5lcj6mw?si=0MjA0t9l8HtrhcBV" # Believer
    m1 = "https://youtu.be/5Ejp7yFZxPM?si=ZkNoQUEKzm9gc4hA" # Cupid
    m2 = "https://youtu.be/kffacxfA7G4?si=y2cZ2GI9v035YB8Q" # Baby
    m3 = "https://youtu.be/8xg3vE8Ie_E?si=Ytxh8ATchaCZE8_Q" # Love Story
    m4 = "https://youtu.be/QcIy9NiNbmo?si=KLS6AslroPae0xAM" # Bad Blood
    print()
    messages = [str(m0), str(m1), str(m2), str(m3), str(m4)]
    aes_keys = [get_random_bytes(16) for _ in range(len(messages))]  # Generate AES keys for messages
    encrypted_messages = [encrypt_message(aes_keys[i], messages[i]) for i in range(len(messages))]
    
    (pubkey, privkey) = rsa.newkeys(512)
    d = privkey.d
    N = pubkey.n
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port = 22552
    server_socket.bind(('', port))
    server_socket.listen(5)
    
    client_socket, addr = server_socket.accept()
    print("Connection Established.")
    print()
    print("Sending RSA public key: ", N)
    print()
    
    saved = pubkey.save_pkcs1(format='DER')
    client_socket.send(saved) 
    
    rand_msg = [random.randint(1,100) for i in range(len(messages))]
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




