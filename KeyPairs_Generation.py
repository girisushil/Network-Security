import random


# Implentation of RSA keypair generation

# for checking auto generated prime numbered of three digits
def checkPrime(n):
    if n <= 1: return False
    # Check if the number is divisible by any integer from 2 to sqrt(num)
    sqrt_num = int(n ** 0.5) + 1
    for x in range(2, sqrt_num):
        if n % x == 0:
            return False
    return True

def Cal_gcd(a, b):
    while b != 0:
        temp = b
        b = a % b
        a = temp
    return a

def Cal_mod_inverse(a, m):
    g, c, z = extended_gcd_algo(a, m)
    if g != 1:
        return None
    else:
        return c % m


# performing recursive approach for finding the gcd and inverse functions for calculation supplements in RSA algorithm
def extended_gcd_algo(a1, a2):
    if a1 == 0:
        return a2, 0, 1

    g, x, y = extended_gcd_algo(a2 % a1, a1)
    new_x = y - (a2 // a1) * x
    new_y = x
    return g, new_x, new_y


def generate_keypair(choice):
    # to generate keypair ((e, n), (d, n))
    if choice == 0:
        p = random.randint(100, 1000)
        while not checkPrime(p):
            p += 1
        q = random.randint(1000, 10000)
        while not checkPrime(q):
            q += 1
        n = p * q
        phi = (p - 1) * (q - 1)
        e = random.randint(2, phi - 1)
        while Cal_gcd(e, phi) != 1:
            e += 1
        d = Cal_mod_inverse(e, phi)
        return (e, n), (d, n)
    else:
        print("Enter Prime numbers p and q")
        p = int(input())
        q = int(input())
        n = p * q
        phi = (p - 1) * (q - 1)
        e = random.randint(2, phi - 1)
        while Cal_gcd(e, phi) != 1:
            e += 1
        d = Cal_mod_inverse(e, phi)
        return (e, n), (d, n)
