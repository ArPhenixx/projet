from Crypto.Cipher import AES
import os

# Fonction pour analyser une chaîne k=v


def parse_kv(input_str):
    """
    Analyse une chaîne au format k=v&k=v... et retourne un dictionnaire.
    """
    pairs = input_str.split("&")
    result = {}
    for pair in pairs:
        key, value = pair.split("=")
        result[key] = value
    return result

# Fonction pour générer un profil utilisateur


def profile_for(email):
    """
    Génère un profil utilisateur encodé au format k=v&k=v.
    """
    if "&" in email or "=" in email:
        raise ValueError("Les caractères '&' et '=' ne sont pas autorisés.")
    profile = f"email={email}&uid=10&role=user"
    return profile

# Génération d'une clé AES aléatoire


def generate_aes_key():
    """
    Génère une clé AES aléatoire.
    """
    return os.urandom(16)

# Fonctions de chiffrement et déchiffrement ECB


def encrypt_ecb(data, key):
    """
    Chiffre les données en mode ECB avec padding PKCS#7.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pkcs7_pad(data.encode(), 16)
    return cipher.encrypt(padded_data)


def decrypt_ecb(ciphertext, key):
    """
    Déchiffre les données en mode ECB et enlève le padding PKCS#7.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(ciphertext)
    return pkcs7_unpad(decrypted_data).decode()

# Fonctions de padding PKCS#7


def pkcs7_pad(data, block_size):
    """
    Applique le padding PKCS#7.
    """
    padding_needed = block_size - (len(data) % block_size)
    return data + bytes([padding_needed] * padding_needed)


def pkcs7_unpad(data):
    """
    Supprime le padding PKCS#7.
    """
    padding_length = data[-1]
    return data[:-padding_length]

# Exploitation pour créer un rôle admin


def create_admin_profile(oracle_encrypt, block_size, key):
    # Bloc contrôlé pour inclure "role=admin" avec padding
    admin_payload = "admin" + "\x0b" * 11  # 11 pour compléter le bloc à 16 octets
    admin_block = encrypt_ecb(profile_for(admin_payload), key)[:block_size]

    # Générer un profil avec un email pour ajuster les blocs
    crafted_email = "foo@bar.com"
    crafted_profile = profile_for(crafted_email)
    ciphertext = encrypt_ecb(crafted_profile, key)

    # Remplacer le dernier bloc avec "role=admin"
    manipulated_ciphertext = ciphertext[:-block_size] + admin_block
    return manipulated_ciphertext


# Programme principal
if __name__ == "__main__":
    # Générer une clé AES
    key = generate_aes_key()

    # Étape 1 : Chiffrement du profil
    email = "foo@bar.com"
    encoded_profile = profile_for(email)
    encrypted_profile = encrypt_ecb(encoded_profile, key)

    # Étape 2 : Déchiffrement
    decrypted_profile = decrypt_ecb(encrypted_profile, key)
    print(f"Déchiffré : {decrypted_profile}")

    # Étape 3 : Exploiter pour obtenir role=admin
    admin_ciphertext = create_admin_profile(encrypt_ecb, 16, key)
    manipulated_profile = decrypt_ecb(admin_ciphertext, key)
    print(f"Profil manipulé : {manipulated_profile}")
