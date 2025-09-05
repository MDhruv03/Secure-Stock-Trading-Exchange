import random

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def lcm(a, b):
    return abs(a * b) // gcd(a, b)

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def generate_paillier_keypair(bits=128):
    p = 47
    q = 59
    n = p * q
    g = n + 1
    lmbda = lcm(p - 1, q - 1)
    mu = mod_inverse(lmbda, n)
    
    public_key = (n, g)
    private_key = (lmbda, mu)
    
    return public_key, private_key

def paillier_encrypt(m, public_key):
    n, g = public_key
    n_sq = n * n
    r = random.randint(1, n - 1)
    c = pow(g, m, n_sq) * pow(r, n, n_sq) % n_sq
    return c

def paillier_decrypt(c, public_key, private_key):
    n, g = public_key
    lmbda, mu = private_key
    n_sq = n * n
    x = pow(c, lmbda, n_sq)
    l_of_x = (x - 1) // n
    m = (l_of_x * mu) % n
    return m
