from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
import base64

# Datos necesarios
key = get_random_bytes(16)  # Clave aleatoria de 128 bits
IV = get_random_bytes(16)   # IV aleatorio de 128 bits para CFB
BLOCK_SIZE_AES = 16 # Bloque de 128 bits
data = "Hola Amigos de Seguridad".encode("utf-8")
print("Mensaje a cifrar con AES-CFB:", data)

# ---- CIFRADO ----

# Creamos un mecanismo de cifrado AES en modo CFB con un vector de inicialización IV
cipher = AES.new(key, AES.MODE_CFB, IV)

# Ciframos haciendo que la variable "data" sea múltiplo del tamaño del bloque
ciphertext = cipher.encrypt(pad(data, BLOCK_SIZE_AES))
print("Mensaje cifrado con AES-CFB:", ciphertext)

# ---- DESCIFRADO ----

# Creamos un mecanismo de (des)cifrado AES en modo CFB con un vector de inicialización IV
decipher_aes = AES.new(key, AES.MODE_CFB, IV)

# Desciframos, eliminamos el padding y recuperamos la cadena
new_data = unpad(decipher_aes.decrypt(ciphertext), BLOCK_SIZE_AES).decode("utf-8", "ignore")
print("Mensaje descifrado con AES-CFB:", new_data)