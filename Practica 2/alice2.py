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

# Alice recibe el nuevo texto cifrado de Bob
nonce_b = socketclient.recibir()
texto_cifrado = socketclient.recibir()
firma_b = socketclient.recibir()
print("Texto cifrado recibido de Bob:", texto_cifrado)

# Descifra la cadena de caracteres
aes_decipher = iniciarAES_CTR_descifrado(k1, nonce_b)
texto_claro = unpad(descifrarAES_CTR(aes_decipher, texto_cifrado), 16)
print("Texto descifrado:", texto_claro.decode("utf-8", "ignore"))

# Comprobamos la firma
if(comprobarRSA_PSS(texto_claro, firma_b, key_pub_b) == True):
    print("La firma es valida.")
else:
    print("La firma no es valida.")

# Alice crea una nueva cadena y la cifra
datos = "Hola Bob".encode("utf-8")
print("Datos a cifrar con AES-CTR-128:", datos)
aes_cipher, nonce_a = iniciarAES_CTR_cifrado(k1)
mensaje_cifradoA = cifrarAES_CTR(aes_cipher, pad(datos, 16))

firma_a2 = firmarRSA_PSS(datos, key_priv_a)

# Envía los paquetes a Bob
socketclient.enviar(nonce_a)
socketclient.enviar(mensaje_cifradoA)
socketclient.enviar(firma_a2)
socketclient.cerrar()