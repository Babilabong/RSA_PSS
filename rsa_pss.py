import random
from hashlib import sha256

# checking if it prime method
def is_prime(n, k=5):
    if n < 2:
        return False
    for p in [2, 3, 5, 7, 11, 13]:
        if n % p == 0 and n != p:
            return False

    s, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for __ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# generate prime method
def generate_prime(bits=512):
    while True:
        p = random.getrandbits(bits)
        p |= (1 << bits - 1) | 1
        if is_prime(p):
            return p

def egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y

# modular inverse method
def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception('there are no modular inverses.')
    return x % m

# generate keys method
def generate_keys():
    p = generate_prime()
    q = generate_prime()
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = modinv(e, phi)
    return (e, n), (d, n)  # public, private

# sign method

def sign(message: bytes, private_key):
    d, n = private_key
    hashed = int.from_bytes(sha256(message).digest(), byteorder='big')
    signature = pow(hashed, d, n)
    return signature

# verify method
def verify(message: bytes, signature: int, public_key):
    e, n = public_key
    hashed = int.from_bytes(sha256(message).digest(), byteorder='big')
    decrypted = pow(signature, e, n)
    return hashed == decrypted


if __name__ == "__main__":
    message = b"message"

    # creating keys
    public_key, private_key = generate_keys()

    print("public Key:", public_key)
    print("private Key:", private_key)

    # create sign
    signature = sign(message, private_key)
    print("signature (integer):", signature)

    # verify the sender
    is_valid = verify(message, signature, public_key)
    print("is the signature valid? ", is_valid)

    # fake message
    is_valid_fake = verify(b"fake message", signature, public_key)
    print("fake message valid? ", is_valid_fake)
