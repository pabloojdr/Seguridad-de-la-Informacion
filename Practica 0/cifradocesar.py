def cifradoCesarAlfabetoInglesMAY(cadena):
    """Devuelve un cifrado Cesar tradicional (+3)"""
    # Definir la nueva cadena de resultado
    resultado = ''
    # Realizar el "cifrado", sabiendo que A = 65, Z = 90, a = 97, z = 122
    i = 0
    while i < len(cadena):
        # Recoge el caracter a cifrar
        ordenClaro = ord(cadena[i])
        ordenCifrado = 0
        # Cambia el caracter a cifrar
        if (ordenClaro >= 65 and ordenClaro <= 90):
            ordenCifrado = (((ordenClaro - 65) + 3) % 26) + 65
        else:
            ordenCifrado = ord(cadena[i])
        # Añade el caracter cifrado al resultado
        resultado = resultado + chr(ordenCifrado)
        i = i + 1
    # Devuelve el resultado
    return resultado

def descifradoCesarAlfabetoInglesMAY(cadena):
    resultado = ''
    i = 0
    while i < len(cadena):
        ordenCifrado = ord(cadena[i])
        ordenClaro = 0
        if (ordenCifrado >= 65 and ordenCifrado <= 90):
            ordenClaro = (((ordenCifrado - 65) - 3) % 26) + 65
        else:
            ordenClaro = ord(cadena[i])
        resultado = resultado + chr(ordenClaro)
        i = i + 1
    return resultado

def cifradoCesarAlfabetoIngles(cadena):
    resultado = ''
    i = 0
    while i < len(cadena):
        ordenClaro = ord(cadena[i])
        ordenCifrado = 0
        if (ordenClaro >= 65 and ordenClaro <= 90):
            ordenCifrado = (((ordenClaro - 65) + 3) % 26) + 65
        elif (ordenClaro >= 97 and ordenClaro <= 122):
            ordenCifrado = (((ordenClaro - 97) + 3) % 26) + 97
        else:
            ordenCifrado = ord(cadena[i])
        resultado = resultado + chr(ordenCifrado)
        i = i + 1
    return resultado

def descifradoCesarAlfabetoIngles(cadena):
    resultado = ''
    i = 0
    while i < len(cadena):
        ordenCifrado = ord(cadena[i])
        ordenClaro = 0
        if (ordenCifrado >= 65 and ordenCifrado <= 90):
            ordenClaro = (((ordenCifrado - 65) - 3) % 26) + 65
        elif (ordenCifrado >= 97 and ordenCifrado <= 122):
            ordenClaro = (((ordenCifrado - 97) - 3) % 26) + 97
        else:
            ordenClaro = ord(cadena[i])
        resultado = resultado + chr(ordenClaro)
        i = i + 1
    return resultado

def cifradoCesarAlfabetoInglesGeneralizado(cadena, desplazamiento):
    resultado = ''
    i = 0
    while i < len(cadena):
        ordenClaro = ord(cadena[i])
        ordenCifrado = 0
        if (ordenClaro >= 65 and ordenClaro <= 90):
            ordenCifrado = (((ordenClaro - 65) + desplazamiento) % 26) + 65
        elif (ordenClaro >= 97 and ordenClaro <= 122):
            ordenCifrado = (((ordenClaro - 97) + desplazamiento) % 26) + 97
        else:
            ordenCifrado = ord(cadena[i])
        resultado = resultado + chr(ordenCifrado)
        i = i + 1
    return resultado

def descifradoCesarAlfabetoInglesGeneralizado(cadena, desplazamiento):
    resultado = ''
    i = 0
    while i < len(cadena):
        ordenCifrado = ord(cadena[i])
        ordenClaro = 0
        if (ordenCifrado >= 65 and ordenCifrado <= 90):
            ordenClaro = (((ordenCifrado - 65) - desplazamiento) % 26) + 65
        elif (ordenCifrado >= 97 and ordenCifrado <= 122):
            ordenClaro = (((ordenCifrado - 97) - desplazamiento) % 26) + 97
        else:
            ordenClaro = ord(cadena[i])
        resultado = resultado + chr(ordenClaro)
        i = i + 1
    return resultado

def main():
    textoClaro = "HOLA MUNDO"
    textoCifrado = cifradoCesarAlfabetoInglesMAY(textoClaro)
    print("Cadena sin cifrar:", textoClaro)
    print("Cadena cifrada:", textoCifrado)
    textoDescifrado = descifradoCesarAlfabetoInglesMAY(textoCifrado)
    print("Cadena descifrada:", textoDescifrado)

    textoClaro2 = "NUEVA cadena PaRA CIFrAR"
    textoCifrado2 = cifradoCesarAlfabetoIngles(textoClaro2)
    print("Cadena a cifrar (mayusculas y minusculas):", textoClaro2)
    print("Cadena cifrada (mayusculas y minusculas):", textoCifrado2)
    textoDescifrado2 = descifradoCesarAlfabetoIngles(textoCifrado2)
    print("Cadena descifrada (mayusculas y minusculas):", textoDescifrado2)

    textoClaro3 = "Hola EsToY prObaNDO a CIFRAR cAdENas"
    textoCifrado3 = cifradoCesarAlfabetoInglesGeneralizado(textoClaro3, 5)
    print("Cadena sin cifrar (generalizado):", textoClaro3)
    print("Cadena cifrada (generalizado):", textoCifrado3)
    textoDescifrado3 = descifradoCesarAlfabetoInglesGeneralizado(textoCifrado3, 5)
    print("Cadena descifrada (generalizado):", textoDescifrado3)


main()