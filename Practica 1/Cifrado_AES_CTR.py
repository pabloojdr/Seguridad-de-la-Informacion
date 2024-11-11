from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
import base64

# Datos necesarios
key = get_random_bytes(16) # Clave aleatoria de 128 bits para AES
nonce = get_random_bytes(8) # Nonce aleatorio de la mitad del tamaño del bloque (64 bits)
BLOCK_SIZE_AES = 16 # Bloque de 128 bits
data = "Hola Amigos de Seguridad".encode("utf-8")
print("Mensaje a cifrar con AES-CTR: ", data)

# ---- CIFRADO ----

# Creamos un mecanismo de cifrado AES en modo CTR con un nonce como parámetro
cipher = AES.new(key, AES.MODE_CTR, nonce = nonce)

# Ciframos haciendo que la variable data sea múltiplo del tamaño de bloque
ciphertext = cipher.encrypt(pad(data, BLOCK_SIZE_AES))
print("Mensaje cifrado con AES-CTR:", ciphertext)

# ---- DESCIFRADO ----

# Creamos un mecanismo de cifrado AES en modo CTR con un nonce
decipher_aes = AES.new(key, AES.MODE_CTR, nonce = nonce)

# Desciframos, eliminamos el padding y recuperamos la cadena
new_data = unpad(decipher_aes.decrypt(ciphertext), BLOCK_SIZE_AES).decode("utf-8", "ignore")
print("Mensaje descifrado con AES-CTR:", new_data)