from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
import base64

# Datos necesarios
key = get_random_bytes(16) # Clave aleatoria de 128 bits
nonce = get_random_bytes(16) # Nonce aleatorio del mismo tamaño de bloque
BLOCK_SIZE_AES = 16 # Bloque de 128 bits
data = "Hola Amigos de Seguridad".encode("utf-8")
print("Mensaje a cifrar con AES-GCM:", data)
mac_size = 16

# ---- CIFRADO ----

# Creamos un mecanismo de cifrado AES en modo GCM con un nonce
cipher = AES.new(key, AES.MODE_GCM, nonce = nonce, mac_len = mac_size)

# Ciframos haciendo que la variable data sea múltiplo del tamaño de bloque
ciphertext, mac_cifrado = cipher.encrypt_and_digest(pad(data, BLOCK_SIZE_AES))
print("Mensaje cifrado con AES-GCM:", ciphertext)

# ---- DESCIFRADO ----
try:
    descipher_aes = AES.new(key, AES.MODE_GCM, nonce = nonce)
    new_data = unpad(descipher_aes.decrypt_and_verify(ciphertext, mac_cifrado), BLOCK_SIZE_AES).decode("utf-8", "ignore")
    print("Mensaje descifrado con AES-GCM:", new_data)
except (ValueError, KeyError) as e:
    print("ERROR")