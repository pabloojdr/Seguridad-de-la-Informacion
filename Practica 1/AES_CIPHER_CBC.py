from Crypto.Random import get_random_bytes
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Util import Counter

class AES_CIPHER_CBC:

    BLOCK_SIZE_AES = 16 # AES: Bloque de 128 bits

    def __init__(self, key):
        """Inicializa las variables locales"""

    def cifrar(self, cadena, IV):
        """Cifra el parámetro cadena (de tipo String) con una IV específica, y 
           devuelve el texto cifrado binario"""
        cipher = AES.new(key, AES.MODE_CBC, IV)
        data = cadena.encode("utf-8")
        ciphertext = cipher.encrypt(pad(data, type(self).BLOCK_SIZE_AES))
        return ciphertext

    def descifrar(self, cifrado, IV):
        """Descifra el parámetro cifrado (de tipo binario) con una IV específica, y 
           devuelve la cadena en claro de tipo String"""
        decipher_aes = AES.new(key, AES.MODE_CBC, IV)
        new_data = unpad(decipher_aes.decrypt(cifrado), type(self).BLOCK_SIZE_AES).decode("utf-8", "ignore")
        return new_data

key = get_random_bytes(16) # Clave aleatoria de 128 bits
IV = get_random_bytes(16)  # IV aleatorio de 128 bits

datos = "Hola Mundo con AES en modo CBC"
print("Mensaje sin cifrar: ", datos)

d = AES_CIPHER_CBC(key)

cifrado = d.cifrar(datos, IV)
print("Mensaje cifrado con AES-CBC: ", cifrado)

descifrado = d.descifrar(cifrado, IV)
print("Mensaje descifrado con AES-CBC:", descifrado)