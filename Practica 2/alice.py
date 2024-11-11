from funciones_rsa import *
from funciones_aes import *
from socket_class import *
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Importamos la clave privada de Alice y la clave publica de Bob
key_priv_a = cargar_RSAKey_Privada("clave_privada_a.txt", "password_alice")
key_pub_b = cargar_RSAKey_Publica("clave_publica_b.txt")

# Creamos un array de 16 bytes y lo ciframos usando la clave de Bob
k1 = get_random_bytes(16)
print("Array K1:", k1)
datos_cifrado = cifrarRSA_OAEP(k1, key_pub_b)

# Firmamos el array K1 con la clave de Alice
firma_a = firmarRSA_PSS(k1, key_priv_a)

# Creamos la conexion y enviamos los datos y la firma
socketclient = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socketclient.conectar()
socketclient.enviar(datos_cifrado)
socketclient.enviar(firma_a)
socketclient.cerrar()

