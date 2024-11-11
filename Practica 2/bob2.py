from funciones_aes import *
from funciones_rsa import *
from socket_class import *
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Cargamos la clave privada de Bob y la clave publica de Alice
key_priv_b = cargar_RSAKey_Privada("clave_privada_b.txt", "password_bob")
key_pub_a = cargar_RSAKey_Publica("clave_publica_a.txt")

# Establecemos la conexion como servidor y recibimos el texto y la firma
socketserver = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socketserver.escuchar()

# Recibe los paquetes del servidor
mensaje_cifrado = socketserver.recibir()
firma = socketserver.recibir()


# Desciframos el array y lo mostramos por pantalla
k1 = descifrarRSA_OAEP(mensaje_cifrado, key_priv_b)
print("Array K1 descifrado:", k1)

# Comprobamos la validez de la firma
if (comprobarRSA_PSS(k1, firma, key_pub_a) == True):
    print("La firma es valida.")
else:
    print("La firma no es valida.")

# Ciframos una nueva cadena
datos = "Hola Alice".encode("utf-8")
print("Datos a cifrar AES-CTR-128:", datos)

aes_cipher, nonce = iniciarAES_CTR_cifrado(k1)
texto_cifrado = cifrarAES_CTR(aes_cipher, pad(datos, 16)) # Se usa 16 bytes para el tamaño de bloque de 128 bits
print("Datos cifrados con AES-CTR:", texto_cifrado)

firma_b = firmarRSA_PSS(datos, key_priv_b)

socketserver.enviar(nonce)
socketserver.enviar(texto_cifrado)
socketserver.enviar(firma_b)

# Bob recibe los paquetes de Alice
nonce_a = socketserver.recibir()
mensaje_cifradoA = socketserver.recibir()
print("Texto cifrado recibido de Alice:", mensaje_cifradoA)
firma_a = socketserver.recibir()

aes_decipher = iniciarAES_CTR_descifrado(k1, nonce_a)
mensaje_claroA = unpad(descifrarAES_CTR(aes_decipher, mensaje_cifradoA), 16)
print("Mensaje descifrado recibido de Alice:", mensaje_claroA.decode("utf-8", "ignore")) # Se usa decode aqui porque si no, al comprobar la firma no funciona

try:
    comprobarRSA_PSS(mensaje_claroA, firma_a, key_pub_a)
    print("La firma es valida.")
except(ValueError, KeyError):
    print("La firma no es valida")

socketserver.cerrar()