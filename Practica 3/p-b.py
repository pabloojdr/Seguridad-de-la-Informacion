from Crypto.Hash import SHA256, HMAC
import base64
import json
import sys
from socket_class import SOCKET_SIMPLE_TCP
import funciones_aes
from Crypto.Random import get_random_bytes

# Paso 0: Inicializacion
########################

# Lee clave KBT
KBT = open("KBT.bin", "rb").read()

# Paso 1) B->T: KBT(Bob, Nb) en AES-GCM
#######################################

# Crear el socket de conexion con T (5551)
print("Creando conexion con T...")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socket.conectar()

# Crea los campos del mensaje
t_n_origen = get_random_bytes(16)

# Codifica el contenido (los campos binarios en una cadena) y construyo el mensaje JSON
msg_TE = []
msg_TE.append("Bob")
msg_TE.append(t_n_origen.hex())
json_TE = json.dumps(msg_TE)
print("B -> T (descifrado): " + json_TE)

# Cifra los datos con AES GCM
aes_engine = funciones_aes.iniciarAES_GCM(KBT)
cifrado, cifrado_mac, cifrado_nonce = funciones_aes.cifrarAES_GCM(aes_engine,json_TE.encode("utf-8"))

# Envia los datos
socket.enviar(cifrado)
socket.enviar(cifrado_mac)
socket.enviar(cifrado_nonce)

# Paso 2) T->B: KBT(K1, K2, Nb) en AES-GCM
##########################################
# (A realizar por el alumno/a...)

# Recibe el mensaje
cifrado2 = socket.recibir()
cifrado_mac2 = socket.recibir()
cifrado_nonce2 = socket.recibir()

datos_descifrado_TE = funciones_aes.descifrarAES_GCM(KBT, cifrado_nonce2, cifrado2, cifrado_mac2)

# Decodifica el contenido: K1, K2, Nb
json_TE2 = datos_descifrado_TE.decode("utf-8", "ignore")
print("T -> B (descifrado): " + json_TE2)
msg_TE2 = json.loads(json_TE2)

# Extraemos el contenido
K1, K2, nb = msg_TE2
K1 = bytearray.fromhex(K1)
K2 = bytearray.fromhex(K2)
nb = bytearray.fromhex(nb)

if(nb == t_n_origen):
    print("Nonce valido.")
else:
    print("ERROR en Nonce")

# Cerramos el socket entre B y T, no lo utilizaremos mas
socket.cerrar() 

# Paso 5) A->B: KAB(Nombre) en AES-CTR con HMAC
###############################################
# (A realizar por el alumno/a...)

# Creamos la conexion con A
socket_BA = SOCKET_SIMPLE_TCP('127.0.0.1', 5552)
print("Esperando a A...")
socket_BA.escuchar()
mensaje_cifradoAB = socket_BA.recibir()
macA = socket_BA.recibir()
nonce_a = socket_BA.recibir()

print("A -> B (sin descifrar): ", mensaje_cifradoAB)
print("A -> B (sin descifrar): ", macA)

# Desciframos el mensaje
aes_decipher_ctr = funciones_aes.iniciarAES_CTR_descifrado(K1, nonce_a)
mensaje_descifradoAB = funciones_aes.descifrarAES_CTR(aes_decipher_ctr, mensaje_cifradoAB)
print("Mensaje descifrado A -> B: " + mensaje_descifradoAB.decode("utf-8", "ignore"))

# Comprobamos el HMAC 
hrecv = HMAC.new(K2, digestmod=SHA256)
hrecv.update(mensaje_descifradoAB)
try:
    hrecv.verify(macA) # .hexverify(macA) en caso de que macA fuese una cadena hexadecimal
    print("El mensaje es autentico.")
except ValueError:
    print("El mensaje o la clave son erroneos.")

# Paso 6) B->A: KAB(Apellido) en AES-CTR con HMAC
#################################################
# (A realizar por el alumno/a...)

# Creamos los datos que vamos a mandar
datos = "Campoy".encode("utf-8")
aes_cipher_ctr, nonce_b = funciones_aes.iniciarAES_CTR_cifrado(K1)
mensaje_cifradoBA = funciones_aes.cifrarAES_CTR(aes_cipher_ctr, datos)

# Creamos la HMAC con K2
hmacB = HMAC.new(K2, datos, digestmod=SHA256)
macB = hmacB.digest()

print("B -> A: ", mensaje_cifradoBA)
print("B -> A: ", macB)

# Enviamos los datos a A
socket_BA.enviar(mensaje_cifradoBA)
socket_BA.enviar(macB)
socket_BA.enviar(nonce_b)


# Paso 7) A->B: KAB(END) en AES-CTR con HMAC
############################################
# (A realizar por el alumno/a...)

# Recibimos los datos de A
mensaje_cifradoAB2 = socket_BA.recibir()
macA2 = socket_BA.recibir()
nonce_a2 = socket_BA.recibir()

print("A -> B (sin descifrar): ", mensaje_cifradoAB2)
print("A -> B (sin descifrar): ", macA2)

# Desciframos el mensaje
aes_decipher_ctr2 = funciones_aes.iniciarAES_CTR_descifrado(K1, nonce_a2)
mensaje_descifradoAB2 = funciones_aes.descifrarAES_CTR(aes_decipher_ctr2, mensaje_cifradoAB2)
print("Mensaje descifrado: " + mensaje_descifradoAB2.decode("utf-8", "ignore"))

# Comprobamos la HMAC
hrecv2 = HMAC.new(K2, digestmod=SHA256)
hrecv2.update(mensaje_descifradoAB2)
try:
    hrecv2.verify(macA2)
    print("El mensaje es auutentico.")
except ValueError:
    print("El mensaje o la clave son erroneos.")

# Cerramos conexion entre B y A, ya no la utilizaremos mas
socket_BA.cerrar()