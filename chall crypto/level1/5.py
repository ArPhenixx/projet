def repeating_key_xor(plaintext, key):
    """
    Applique le XOR avec une clé répétée sur un texte clair.

    :param plaintext: Texte clair sous forme de bytes
    :param key: Clé sous forme de bytes
    :return: Texte chiffré sous forme de bytes
    """
    ciphertext = bytearray()
    key_length = len(key)

    for i in range(len(plaintext)):
        # Appliquer XOR entre le byte du plaintext et le byte correspondant de la clé (modulo la longueur de la clé)
        ciphertext.append(plaintext[i] ^ key[i % key_length])

    return bytes(ciphertext)


# Texte clair
plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"

# Clé
key = b"ICE"

# Chiffrement
ciphertext = repeating_key_xor(plaintext, key)

# Affichage du résultat chiffré sous forme hexadécimale
print(ciphertext.hex())
