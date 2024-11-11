from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
import base64

# Datos necesarios
key = get_random_bytes(16) # Clave aleatoria de 128 bits
BLOCK_SIZE_AES = 16 # AES: Bloque de 128 bits
data = "Hola Amigos de Seguridad".encode("utf-8") # Datos a cifrar
print("Mensaje a cifrar con AES-ECB:", data)

# ---- CIFRADO ----

# Mecanismo de cifrado AES en modo ECB, por lo que solo es necesario la key
cipher = AES.new(key, AES.MODE_ECB)

# Ciframos haciendo que la variable "data" sea múltiplo del tamaño del bloque
ciphertext = cipher.encrypt(pad(data, BLOCK_SIZE_AES))
print("Mensaje cifrado con AES-ECB:", ciphertext)

# ---- DESCIFRADO ----

# Mecanismo de (des)cifrado AES en modo ECB, por lo que solo es necesario la key
decipher_aes = AES.new(key, AES.MODE_ECB)

# Desciframos, eliminamos el padding y recuperamos la cadena
new_data = unpad(decipher_aes.decrypt(ciphertext), BLOCK_SIZE_AES).decode("utf-8", "ignore")
print("Mensaje descifrado con AES-ECB:", new_data)