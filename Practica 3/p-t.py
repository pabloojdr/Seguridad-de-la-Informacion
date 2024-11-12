from Crypto.Hash import SHA256, HMAC
import base64
import json
import sys
from socket_class import SOCKET_SIMPLE_TCP
import funciones_aes

# Paso 0: Crea las claves que T comparte con B y A
##################################################

# Crear Clave KAT, guardar a fichero
KAT = funciones_aes.crear_AESKey()
FAT = open("KAT.bin", "wb")
FAT.write(KAT)
FAT.close()

# Crear Clave KBT, guardar a fichero
KBT = funciones_aes.crear_AESKey()
FBT = open("KBT.bin", "wb")
FBT.write(KBT)
FBT.close()

# Paso 1) B->T: KBT(Bob, Nb) en AES-GCM
#######################################

# Crear el socket de escucha de Bob (5551)
print("Esperando a Bob...")
socket_Bob = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socket_Bob.escuchar()

# Crea la respuesta para B y A: K1 y K2
K1 = funciones_aes.crear_AESKey()
K2 = funciones_aes.crear_AESKey()

# Recibe el mensaje
cifrado = socket_Bob.recibir()
cifrado_mac = socket_Bob.recibir()
cifrado_nonce = socket_Bob.recibir()

# Descifro los datos con AES GCM
datos_descifrado_ET = funciones_aes.descifrarAES_GCM(KBT, cifrado_nonce, cifrado, cifrado_mac)

# Decodifica el contenido: Bob, Nb
json_ET = datos_descifrado_ET.decode("utf-8" ,"ignore")
print("B -> T (descifrado): " + json_ET)
msg_ET = json.loads(json_ET)

# Extraigo el contenido
t_bob, t_nb = msg_ET
t_nb = bytearray.fromhex(t_nb)

# Paso 2) T->B: KBT(K1, K2, Nb) en AES-GCM
##########################################
# (A realizar por el alumno/a...)

msg_ET2 = []
msg_ET2.append(K1.hex())
msg_ET2.append(K2.hex())
msg_ET2.append(t_nb.hex())
json_ET2 = json.dumps(msg_ET2)
print("T -> B (descifrado): " + json_ET2)

# Cifra los datos con AES GCM
aes_engine = funciones_aes.iniciarAES_GCM(KBT)
cifrado2, cifrado_mac2, cifrado_nonce2 = funciones_aes.cifrarAES_GCM(aes_engine, json_ET2.encode("utf-8"))

# Envia los datos
socket_Bob.enviar(cifrado2)
socket_Bob.enviar(cifrado_mac2)
socket_Bob.enviar(cifrado_nonce2)

# Cerramos el socket entre B y T, no lo utilizaremos mas
socket_Bob.cerrar() 

# Paso 3) A->T: KAT(Alice, Na) en AES-GCM
#########################################
# (A realizar por el alumno/a...)

# Crear el socket de escucha de Alice
print("Esperando a Alice...")
socket_Alice = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socket_Alice.escuchar()

# Recibe el mensaje
cifradoA = socket_Alice.recibir()
cifrado_macA = socket_Alice.recibir()
cifrado_nonceA = socket_Alice.recibir()

# Descifro los datos con AES GCM
datos_descifrado_ET_A = funciones_aes.descifrarAES_GCM(KAT, cifrado_nonceA, cifradoA, cifrado_macA)

# Decodifico el contenido: Alice, Na
json_ET_A = datos_descifrado_ET_A.decode("utf-8", "ignore")
print("A -> T (descifrado): " + json_ET_A)
msg_ET_A = json.loads(json_ET_A)

# Extraigo el contenido
t_alice, t_na = msg_ET_A
t_na = bytearray.fromhex(t_na)

# Paso 4) T->A: KAT(K1, K2, Na) en AES-GCM
##########################################
# (A realizar por el alumno/a...)

msg_ET3 = []
msg_ET3.append(K1.hex())
msg_ET3.append(K2.hex())
msg_ET3.append(t_na.hex())
json_ET3 = json.dumps(msg_ET3)
print("T -> A (descifrado): " + json_ET3)

# Cifra los datos
aes_cipher = funciones_aes.iniciarAES_GCM(KAT)
cifrado3, cifrado_mac3, cifrado_nonce3 = funciones_aes.cifrarAES_GCM(aes_cipher, json_ET3.encode("utf-8"))

# Envia los sockets a A
socket_Alice.enviar(cifrado3)
socket_Alice.enviar(cifrado_mac3)
socket_Alice.enviar(cifrado_nonce3)

# Cerramos el socket entre A y T, ya no lo utilizaremos más
socket_Alice.cerrar()
