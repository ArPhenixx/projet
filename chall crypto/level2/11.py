import os
from Crypto.Cipher import AES
from random import randint


def random_aes_key():
    """Génère une clé AES aléatoire de 16 octets."""
    return os.urandom(16)


def encryption_oracle(input_data):
    """
    Fonction qui chiffre les données avec un mode ECB ou CBC aléatoire.
    """
    # Génère une clé AES aléatoire
    key = random_aes_key()

    # Ajoute 5 à 10 octets aléatoires avant et après le plaintext
    prefix = os.urandom(randint(5, 10))
    suffix = os.urandom(randint(5, 10))
    plaintext = prefix + input_data + suffix

    # Décide aléatoirement entre ECB et CBC
    if randint(0, 1) == 0:
        # Chiffrement en mode ECB
        cipher = AES.new(key, AES.MODE_ECB)
        padded_plaintext = pkcs7_pad(plaintext, AES.block_size)
        return cipher.encrypt(padded_plaintext)
    else:
        # Chiffrement en mode CBC
        iv = os.urandom(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_plaintext = pkcs7_pad(plaintext, AES.block_size)
        return cipher.encrypt(padded_plaintext)


def pkcs7_pad(data, block_size):
    """Ajoute un padding PKCS#7."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def detect_encryption_mode(ciphertext):
    """
    Détecte si le mode de chiffrement est ECB ou CBC.
    Si des blocs identiques sont détectés, c'est probablement ECB.
    """
    block_size = AES.block_size
    blocks = [ciphertext[i:i+block_size]
              for i in range(0, len(ciphertext), block_size)]
    if len(blocks) != len(set(blocks)):
        return "ECB"
    else:
        return "CBC"


# Test
if __name__ == "__main__":
    # Données de test (un grand bloc répétitif pour mieux détecter ECB)
    test_data = b"A" * 64

    # Exécute plusieurs tests
    for _ in range(10):
        ciphertext = encryption_oracle(test_data)
        mode_detected = detect_encryption_mode(ciphertext)
        print(f"Mode détecté : {mode_detected}")
