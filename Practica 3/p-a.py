
from Crypto.Hash import SHA256, HMAC
import base64
import json
import sys
from socket_class import SOCKET_SIMPLE_TCP
import funciones_aes
from Crypto.Random import get_random_bytes

# Paso 0: Inicializacion
########################
# (A realizar por el alumno/a...)

# Lee la clave KAT
KAT = open("KAT.bin", "rb").read()


# Paso 3) A->T: KAT(Alice, Na) en AES-GCM
#########################################
# (A realizar por el alumno/a...)

# Crear el socket de conexión con T (5551)
print("Creando conexion con T...")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socket.conectar()

# Crea los campos del mensaje
t_n_origen = get_random_bytes(16)

# Codifica el contenido (los campos binarios en una cadena) y construyo el mensaje JSON
msg_TE = []
msg_TE.append("Alice")
msg_TE.append(t_n_origen.hex())
json_TE = json.dumps(msg_TE)
print("A -> T (descifrado): " + json_TE)

# Cifra los datos con AES GCM
aes_engine = funciones_aes.iniciarAES_GCM(KAT)
cifrado, cifrado_mac, cifrado_nonce = funciones_aes.cifrarAES_GCM(aes_engine, json_TE.encode("utf-8"))

# Envia los datos
socket.enviar(cifrado)
socket.enviar(cifrado_mac)
socket.enviar(cifrado_nonce)

# Paso 4) T->A: KAT(K1, K2, Na) en AES-GCM
##########################################
# (A realizar por el alumno/a...)

# Recibimos el mensaje de T
cifrado3 = socket.recibir()
cifrado_mac3 = socket.recibir()
cifrado_nonce3 = socket.recibir()

# Desciframos el mensaje
datos_descifrado_TA = funciones_aes.descifrarAES_GCM(KAT, cifrado_nonce3, cifrado3, cifrado_mac3)

# Decodifica el contenido
json_TE3 = datos_descifrado_TA.decode("utf-8", "ignore")
print("T -> A (descifrado): " + json_TE3)
msg_TE3 = json.loads(json_TE3)

# Extraemos el contenido
K1, K2, na = msg_TE3
K1 = bytearray.fromhex(K1)
K2 = bytearray.fromhex(K2)
na = bytearray.fromhex(na)

if(na == t_n_origen):
    print("Nonce valido.")
else:
    print("ERROR en Nonce")

# Cerramos el socket entre A y T, ya no lo utilizaremos más
socket.cerrar()

# Paso 5) A->B: KAB(Nombre) en AES-CTR con HMAC
###############################################
# (A realizar por el alumno/a...)

# Creamos el mensaje que se quiere mandar y lo codificamos
mensaje = "Pablo".encode("utf-8")

# Ciframos el mensaje usando CTR y K1
aes_cipher_ctr, nonce_a = funciones_aes.iniciarAES_CTR_cifrado(K1)
mensaje_cifrado = funciones_aes.cifrarAES_CTR(aes_cipher_ctr, mensaje)

# Creamos el HMAC con la K2
hmacA = HMAC.new(K2, mensaje, digestmod=SHA256)
macA = hmacA.digest() # .hexdigest() como cadena de caracteres hexadecimales

print("A -> B: ", mensaje_cifrado)
print("A -> B: ", macA)

# Creamos la conexión entre A y B
socket_AB = SOCKET_SIMPLE_TCP('127.0.0.1', 5552)
socket_AB.conectar()
socket_AB.enviar(mensaje_cifrado)
socket_AB.enviar(macA)
socket_AB.enviar(nonce_a)

# Paso 6) B->A: KAB(Apellido) en AES-CTR con HMAC
#################################################
# (A realizar por el alumno/a...)

# Obtenemos los datos mandados por B
mensaje_cifradoBA = socket_AB.recibir()
macB = socket_AB.recibir()
nonce_b = socket_AB.recibir()

print("B -> A (sin descifrar): ", mensaje_cifradoBA)
print("B -> A (sin descifrar): ", macB)

# Desciframos el mensaje
aes_decipher_ctr = funciones_aes.iniciarAES_CTR_descifrado(K1, nonce_b)
mensaje_descifradoBA = funciones_aes.descifrarAES_CTR(aes_decipher_ctr, mensaje_cifradoBA)
print("Mensaje descifrado B -> A: " + mensaje_descifradoBA.decode("utf-8", "ignore"))

# Comprobamos el HMAC
hrecv = HMAC.new(K2, digestmod=SHA256)
hrecv.update(mensaje_descifradoBA)
try:
    hrecv.verify(macB)
    print("El mensaje es autentico.")
except ValueError:
    print("El mensaje o la clave son erroneos.")

# Paso 7) A->B: KAB(END) en AES-CTR con HMAC
############################################
# (A realizar por el alumno/a...)

# Creamos los datos que queremos mandar
datos2 = "END".encode("utf-8")

# Ciframos el mensaje con K1 y AES (CTR)
aes_cipher_ctr2, nonce_a2 = funciones_aes.iniciarAES_CTR_cifrado(K1)
mensaje_cifrado_AB2 = funciones_aes.cifrarAES_CTR(aes_cipher_ctr2, datos2)

# Creamos el HMAC con K2
hmacA2 = HMAC.new(K2, datos2, digestmod=SHA256)
macA2 = hmacA2.digest()

print("A -> B: ", mensaje_cifrado_AB2)
print("A -> B: ", macA)

# Enviamos a B los datos
socket_AB.enviar(mensaje_cifrado_AB2)
socket_AB.enviar(macA2)
socket_AB.enviar(nonce_a2)

# Cerramos la conexion entre A y B, ya no la utilizaremos mas
socket_AB.cerrar()