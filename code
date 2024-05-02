# This script implements a simple version of the Diffie-Hellman key exchange protocol.

# Import the random module
import random
# Import the math module
import math    # Import the hashlib module
# Import the hashlib module
import hashlib

# This function isPrime(number) checks if a given number is prime.

def isPrime(number):
    # Check if the number is 2
    if number == 2:
        # If the number is 2, return True
        return True
    # Check if the number is even
    if number % 2 == 0:
        # If the number is even, return False
        return False
    # Calculate the square root of the number
    sqrt = math.sqrt(number)
    # Convert the square root to an integer
    sqrt = int(sqrt)
    # Iterate from 3 to the square root of the number
    for i in range(3, sqrt + 1, 2):
        # Check if the number is divisible by i
        if number % i == 0:
            # If the number is divisible by i, return False
            return False
    # If the number is not divisible by any number from 3 to the square root of the number, return True
    return True


# This function generates a random prime number greater than 10 and less than 100

def generatePrime():
    # Generate a random number between 10 and 100
    num = random.randint(10, 100000)
    # Check if the number is prime
    while not isPrime(num):
        # If the number is not prime, generate a new number
        num = random.randint(10, 100000)
    # Return the prime number
    return num


#This function calculates a primitive root of a given prime number.

def primitiveRoot(prime):
    # Iterate from 2 to the prime number
    for i in range(2, prime):
        # Initialize a list to store the powers of i
        powers = []
        # Iterate from 1 to the prime number
        for j in range(1, prime):
            # Calculate the power of i modulo the prime number
            power = (i ** j) % prime
            # Check if the power is in the list of powers
            if power in powers:
                # If the power is in the list of powers, break the loop
                break
            # Add the power to the list of powers
            powers.append(power)
        # Check if all the numbers from 1 to the prime number are in the list of powers
        if len(powers) == prime - 1:
            # If all the numbers from 1 to the prime number are in the list of powers, return i
            return i
    # If no primitive root is found, return None
    return None

p = generatePrime()
g = primitiveRoot(p)

# Now we generate Alice's private key
a = random.randint(1, p - 1)
# Now we calculate Alice's public key
A = (g ** a) % p
# Now we generate Bob's private key
b = random.randint(1, p - 1)
# Now we calculate Bob's public key
B = (g ** b) % p
# Alice calculates the shared secret key
shared_secret_key_A = (B ** a) % p
# Bob calculates the shared secret key
shared_secret_key_B = (A ** b) % p
# Check if the shared secret keys are equal
print("DH Key Exchange Protocol:")
if shared_secret_key_A == shared_secret_key_B:
    print("Shared secret keys match!")

else:
    print("Shared secret keys do not match!")

# This function prints a table with three columns: Alice, Bob and Eve. The table shows a, b, A, B, and S for Alice, Bob and Eve.
# Eve is an eavesdropper who intercepts the public keys A and B exchanged between Alice and Bob.

def printTable(a, b, A, B, Sa, Sb):
    # Print the table header
    print("Alice\tBob\t\tEve")

    # Print the values of a, b, A, B, and S for Alice, Bob and Eve
    print(str(a) + "\t\t" + str(b) + "\t\t" + "Nothing")
    print(str(A) + "\t\t" + str(B) + "\t\t" + "Alice and Bob's public keys")
    print(str(Sa) + "\t\t" + str(Sb) + "\t\t" + str((A ** B) % p))


# This function encrypts a message using the hash of the common secret as key.

def encrypt(message, key):
    # First we create a hash object
    h = hashlib.sha256()
    # We update the hash object with the key
    h.update(str(key).encode())
    # We get the digest of the hash object
    key = h.digest()
    print(f"key = {key}")
    # Now, me calculate the length of the key
    key_length = len(key)
    # We initialize the encrypted message
    encrypted_message = ""
    # We iterate over chunks of the message with the same size as the key, and XOR each chunk with the key
    for i in range(0, len(message), key_length):
        # We get a chunck of the message:
        chunk = message[i:i + key_length]
        # Now we XOR the chunk with the key bit-by-bit
        for j in range(len(chunk)):
            encrypted_message += chr(ord(chunk[j]) ^ key[j])
    # We return the encrypted message
    return encrypted_message

# Now let's encrypt a message using the shared secret key
# The message comes from a file called message.txt
with open("message.txt", "r") as file:
    message = file.read()

encrypted_message = encrypt(message, shared_secret_key_A)


# This function decrypts a message using the hash of the common secret as key.

def decrypt(encrypted_message, key):
    # First we create a hash object
    h = hashlib.sha256()
    # We update the hash object with the key
    h.update(str(key).encode())
    # We get the digest of the hash object
    key = h.digest()
    # Now, me calculate the length of the key
    key_length = len(key)
    # We initialize the decrypted message
    decrypted_message = ""
    # We iterate over chunks of the message with the same size as the key, and XOR each chunk with the key
    for i in range(0, len(encrypted_message), key_length):
        # We get a chunck of the message:
        chunk = encrypted_message[i:i + key_length]
        # Now we XOR the chunk with the key bit-by-bit
        for j in range(len(chunk)):
            decrypted_message += chr(ord(chunk[j]) ^ key[j])
    # We return the decrypted message
    return decrypted_message

# Now let's decrypt the message using the shared secret key
decrypted_message = decrypt(encrypted_message, shared_secret_key_B)

print("Diffie-Hellman Key Exchange Protocol implementation:")
printTable(a, b, A, B, shared_secret_key_A, shared_secret_key_B)
print(f"Encrypted message: {encrypted_message}")
print(f"Decrypted message: {decrypted_message}")
