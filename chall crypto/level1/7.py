from Crypto.Cipher import AES
import base64


def decrypt_aes_ecb(ciphertext, key):
    """
    Déchiffre un texte chiffré avec AES-128 en mode ECB.

    :param ciphertext: Texte chiffré sous forme de bytes
    :param key: Clé sous forme de bytes (16 octets)
    :return: Texte déchiffré sous forme de bytes
    """
    cipher = AES.new(
        key, AES.MODE_ECB)  # Initialisation du déchiffreur en mode ECB
    plaintext = cipher.decrypt(ciphertext)  # Déchiffrement
    return plaintext


# Clé donnée
key = b"YELLOW SUBMARINE"  # La clé doit être exactement de 16 octets

# Chargement et décodage du fichier base64
with open('/home/sebastien/Downloads/7.txt', 'r') as file:
    ciphertext_base64 = file.read()

ciphertext = base64.b64decode(ciphertext_base64)  # Décodage Base64

# Déchiffrement
plaintext = decrypt_aes_ecb(ciphertext, key)

# Affichage du texte déchiffré
print(plaintext.decode('utf-8', errors='replace'))
