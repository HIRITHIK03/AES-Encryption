from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt

def encrypt(plaintext, password):
    salt = get_random_bytes(16)
    key = scrypt(password, salt, 32, N=2**14, r=8, p=1)
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    return salt + nonce + ciphertext + tag

def decrypt(ciphertext, password):
    salt, nonce, ciphertext, tag = ciphertext[:16], ciphertext[16:32], ciphertext[32:-16], ciphertext[-16:]
    key = scrypt(password, salt, 32, N=2**14, r=8, p=1)
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted.decode('utf-8')



plaintext = input("Enter the secret message ")
password = input("Enter the secret pw ")
ciphertext = encrypt(plaintext, password)
print("Original message:", plaintext)
print("Encrypted message:", ciphertext)


Password = input("Enter the secret pw ")
decrypted_plaintext = decrypt(ciphertext, Password)
print("Original message:", plaintext)
print("Decrypted message:", decrypted_plaintext)

    



