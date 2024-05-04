#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import rsa 		# For access to RSA algorithm
import socket 	# For socket interaction
import pickle	# For sending arrays across	
import random	# For pseudo-random number generation

# Globals

b = int(input("Enter the index of the message you want (0 or 1): "))  # The index of the message we want (m_b)
k = random.randint(0,1000)	# Random number

# Modular Exponentiation

def mod_exp(k, e, N):
	if(e == 0):
		return 1
	ans = mod_exp(k, e//2, N)%N
	ans = (ans * ans)%N
	if(e%2 == 1):
		ans = (ans * k)%N
	return ans

# Client Setup

s = socket.socket()         

port = 12345               
 
# connect to the server on local computer 
s.connect(('127.0.0.1', port)) 
print("Connection Established")

# Client Server Interaction

def main():
    saved_key = s.recv(1024)
    print("Received public key")
    key = rsa.key.PublicKey.load_pkcs1(saved_key, format='DER')
    N, e = (key.n, key.e)
    
    
    x = s.recv(1024)
    x = pickle.loads(x)
    print("Received random messages")
    
    v = (x[b] + mod_exp(k, e, N))%N
    s.send(f"{v}".encode())
    print("Sending v")
    
    m_ = s.recv(1024)
    print("Received m'")
    m_ = pickle.loads(m_)
    
    m = (m_[b] - k) % N
    print("Requested message: ", m)
    
    _m_ = (m_[1 - b] - k) % N
    print("Trying to access the other message: ", _m_)
    
    print("Closing connection")
    s.close() 

main()


# In[ ]:




