from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# Step 1: Generate parameters for DH
parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())

# Step 2: Alice generates her keys
alice_private_key = parameters.generate_private_key()
alice_public_key = alice_private_key.public_key()

# Bob's choice bit
c = 0 # Change this to 1 to test the other scenario

# Step 3: Bob generates his keys accordingly
bob_private_key = parameters.generate_private_key()
if c == 0:
    bob_public_key = bob_private_key.public_key()
else:
    # Compute Ag^b
    bob_public_key = parameters.parameter_numbers().g ** (bob_private_key.private_numbers().x + alice_private_key.private_numbers().x) % parameters.parameter_numbers().p

# Step 4: Compute shared secrets and derive keys
alice_shared_key_0 = alice_private_key.exchange(bob_public_key)  # Corresponds to g^(ab)
alice_public_num = alice_public_key.public_numbers().y
bob_public_num = bob_public_key.public_numbers().y
p = parameters.parameter_numbers().p

B_div_A = (bob_public_num * pow(alice_public_num, p-2, p)) % p
alice_shared_key_1 = pow(B_div_A, alice_private_key.private_numbers().x, p)

def derive_key(shared_key):
    if isinstance(shared_key, int):
        shared_key = shared_key.to_bytes((shared_key.bit_length() + 7) // 8, 'big')
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)

k0 = derive_key(alice_shared_key_0)
k1 = derive_key(alice_shared_key_1)

# Simulate Bob's ability to derive his selected key
bob_derived_key = derive_key(bob_private_key.exchange(alice_public_key))

# Print results
print(f"Bob's choice bit: {c}")
print(f"Key k0: {k0.hex()}")
print(f"Key k1: {k1.hex()}")
print(f"Bob's derived key: {bob_derived_key.hex()}")

# Verify if Bob's derived key matches his choice
if c == 0 and bob_derived_key.hex() == k0.hex():
    print("Bob successfully derived k0.")
elif c == 1 and bob_derived_key.hex() == k1.hex():
    print("Bob successfully derived k1.")
else:
    print("Bob could not derive the correct key, or derived the wrong key.")
