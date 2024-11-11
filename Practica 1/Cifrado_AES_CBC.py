from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
import base64

# Datos necesarios
key = get_random_bytes(16)  # Clave aleatoria de 128 bits
IV = get_random_bytes(16)   # IV aleatorio de 128 bits para CFB
BLOCK_SIZE_AES = 16 # Bloque de 128 bits
data = "Hola Amigos de la seguridad".encode("utf-8") # Primer dato a cifrar
print("Primer mensaje a cifrar con AES-CBC: ", data)
data1 = "Hola Amigas de la seguridad".encode("utf-8")
print("Segundo mensaje a cifrar con AES-CBC: ", data1)

# ---- CIFRADO ----

# Creamos un mecanismo de cifrado AES en modo CFB con un vector de inicialización IV
cipher = AES.new(key, AES.MODE_CBC, IV)

# Ciframos haciendo que la variable data y data1 sea múltiplo del tamaño del bloque
ciphertext = cipher.encrypt(pad(data, BLOCK_SIZE_AES))
print("Primer mensaje cifrado con AES-CBC: ", ciphertext)

ciphertext1 = cipher.encrypt(pad(data1, BLOCK_SIZE_AES))
print("Segundo mensaje cifrado con AES-CBC: ", ciphertext1)

# ---- DESCIFRADO ----

# Creamos un mecanismo de (des)cifrado AES en modo CFB con un vector de inicialización IV
# Ambos, cifrado y descifrado, se crean de la misma forma
decipher_aes = AES.new(key, AES.MODE_CBC, IV)

# Desciframos, eliminamos el padding y recuperamos la cadena
new_data = unpad(decipher_aes.decrypt(ciphertext), BLOCK_SIZE_AES).decode("utf-8", "ignore")
print("Primer mensaje descifrado con AES-CBC:", new_data)

new_data1 = unpad(decipher_aes.decrypt(ciphertext1), BLOCK_SIZE_AES).decode("utf-8", "ignore")
print("Segundo mensaje descifrado con AES-CBC: ", new_data1)