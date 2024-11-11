from funciones_rsa import *

# Creamos la clave RSA para Alice (2048 bits)
key_a = crear_RSAKey()

# Exportamos las claves privada y publica de Alice a dos ficheros
guardar_RSAKey_Privada("clave_privada_a.txt", key_a, "password_alice")
guardar_RSAKey_Publica("clave_publica_a.txt", key_a)

# Creamos la clave RSA para Bob (2048 bits)
key_b = crear_RSAKey()

# Exportamos las claves privada y publida de Bob a dos ficheros
guardar_RSAKey_Privada("clave_privada_b.txt", key_b, "password_bob")
guardar_RSAKey_Publica("clave_publica_b.txt", key_b)

