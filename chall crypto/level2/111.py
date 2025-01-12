import os
from Crypto.Cipher import AES
import random


def generate_aes_key():
    """
    Génère une clé AES aléatoire de 16 octets.
    """
    return os.urandom(16)


def pkcs7_pad(data, block_size):
    """
    Applique le padding PKCS#7.
    """
    padding_needed = block_size - (len(data) % block_size)
    return data + bytes([padding_needed] * padding_needed)


def encryption_oracle(input_data):
    """
    Fonction d'oracle qui chiffre les données avec ECB ou CBC.

    :param input_data: Données à chiffrer
    :return: Données chiffrées
    """
    # Génération de 5 à 10 octets aléatoires avant et après le texte
    prefix = os.urandom(random.randint(5, 10))
    suffix = os.urandom(random.randint(5, 10))

    # Ajout des octets au texte d'entrée
    plaintext = prefix + input_data + suffix

    # Générer une clé AES aléatoire
    key = generate_aes_key()

    # Décision aléatoire entre ECB et CBC
    use_ecb = random.choice([True, False])

    if use_ecb:
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(pkcs7_pad(plaintext, AES.block_size))
    else:
        iv = os.urandom(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pkcs7_pad(plaintext, AES.block_size))

    return ciphertext, "ECB" if use_ecb else "CBC"


def detect_encryption_mode(oracle_function):
    """
    Détecte si l'oracle chiffre en ECB ou CBC.

    :param oracle_function: Fonction oracle de chiffrement
    :return: Mode de chiffrement détecté ("ECB" ou "CBC")
    """
    # Générer un input connu avec des blocs répétitifs
    input_data = b"A" * 64  # Deux blocs identiques de 16 octets

    # Obtenir les données chiffrées
    ciphertext, actual_mode = oracle_function(input_data)

    # Découper en blocs de 16 octets
    blocks = [ciphertext[i:i + AES.block_size]
              for i in range(0, len(ciphertext), AES.block_size)]

    # Si des blocs identiques existent, c'est probablement ECB
    if len(blocks) != len(set(blocks)):
        detected_mode = "ECB"
    else:
        detected_mode = "CBC"

    return detected_mode, actual_mode


# Exemple d'utilisation
if __name__ == "__main__":
    for _ in range(1):  # Tester plusieurs fois
        detected_mode, actual_mode = detect_encryption_mode(encryption_oracle)
        print(f"Mode détecté : {detected_mode} | Mode réel : {actual_mode}")
