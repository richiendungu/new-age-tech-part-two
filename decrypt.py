from cryptography.hazmat.primitives.ciphers import cipher,algorithms,modes
from cryptography.hazmat.Primitives import padding
from cryptography.hazmat.backends import default_backend


# Encryption function
def encrypt_password(key, password):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(password.encode("utf-8"), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode("utf-8")
    ciphertext = base64.b64encode(ciphertext).decode("utf-8")
    return iv + ciphertext


# Decryption function
def decrypt_password(key, encrypted_password):
    iv = base64.b64decode(encrypted_password[:24])
    ciphertext = base64.b64decode(encrypted_password[24:])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_password = unpad(cipher.decrypt(ciphertext), AES.block_size).decode(
        "utf-8"
    )
    return decrypted_password


# Example usage
encryption_key = b"thisisa16byteskey"
password = "mysecretpassword"

encrypted_password = encrypt_password(encryption_key, password)
print("Encrypted Password:", encrypted_password)

decrypted_password = decrypt_password(encryption_key, encrypted_password)
print("Decrypted Password:", decrypted_password)
