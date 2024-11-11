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

# Cerramos el servidor
socketserver.cerrar()
