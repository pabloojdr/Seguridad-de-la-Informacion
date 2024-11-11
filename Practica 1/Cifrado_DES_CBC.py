from Crypto.Random import get_random_bytes
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
import base64

key = get_random_bytes(8)   # Clave aleatoria de 64 bits
IV = get_random_bytes(8)    # IV aleatorio de 64 bits para CBC
BLOCK_SIZE_DES = 8 # Bloque de 64 bits
data1 = "Hola amigos de la seguridad".encode("utf-8") # Primer dato a cifrar
print("Primer mensaje a cifrar:", data1)
data2 = "Hola amigas de la seguridad".encode("utf-8")
print("Segundo mensaje a cifrar:", data2)

# ---- CIFRADO ----

# Creamos un mecanismo de cifrado DES en modo CBC con un vector de incialización IV
cipher = DES.new(key, DES.MODE_CBC, IV)

# Ciframos haciendo que la variable data1 y data2 sea múltiplo del tamaño del bloque
ciphertext1 = cipher.encrypt(pad(data1, BLOCK_SIZE_DES))
print("Primer mensaje cifrado:", ciphertext1)

ciphertext2 = cipher.encrypt(pad(data2, BLOCK_SIZE_DES))
print("Segundo mensaje cifrado:", ciphertext2)

# ---- DESCIFRADO ----

# Creamos un mecanismo de (des)cifrado DES en modo CBC con un vector de inicialización IV para CBC
# Ambos, cifrado y descifrado, se crean de la misma forma
decipher_des = DES.new(key, DES.MODE_CBC, IV)

# Desciframos, eliminamos el padding y recuperamos las cadenas
new_data1 = unpad(decipher_des.decrypt(ciphertext1), BLOCK_SIZE_DES).decode("utf-8", "ignore")
print("Primer mensaje descifrado:", new_data1)

new_data2 = unpad(decipher_des.decrypt(ciphertext2), BLOCK_SIZE_DES).decode("utf-8", "ignore")
print("Segundo mensaje descifrado:", new_data2)