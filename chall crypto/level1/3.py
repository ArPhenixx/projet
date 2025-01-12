import string

# Fonction pour calculer un score de fréquence des caractères
# Basé sur la fréquence des lettres en anglais
english_frequencies = {
    'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253, 'e': 12.702,
    'f': 2.228, 'g': 2.015, 'h': 6.094, 'i': 6.966, 'j': 0.153,
    'k': 0.772, 'l': 4.025, 'm': 2.406, 'n': 6.749, 'o': 7.507,
    'p': 1.929, 'q': 0.095, 'r': 5.987, 's': 6.327, 't': 9.056,
    'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150, 'y': 1.974, 'z': 0.074,
    ' ': 13.0  # L'espace est très fréquent dans les textes en anglais
}


def score_text(text):
    # Calculer un score basé sur la fréquence des caractères
    return sum(english_frequencies.get(chr(char).lower(), 0) for char in text)


def single_byte_xor(input_bytes, key):
    # Applique un XOR avec une seule clé sur chaque octet de l'entrée
    return bytes([byte ^ key for byte in input_bytes])


def decrypt_single_byte_xor(ciphertext):
    best_score = 0
    best_result = None
    best_key = None

    for key in range(256):  # Tester toutes les clés possibles (0 à 255)
        # Déchiffrer avec la clé actuelle
        plaintext = single_byte_xor(ciphertext, key)
        score = score_text(plaintext)  # Calculer le score du texte déchiffré

        if score > best_score:  # Garder le meilleur résultat
            best_score = score
            best_result = plaintext
            best_key = key

    return best_key, best_result  # Retourner la meilleure clé et le texte déchiffré


# Chaîne hexadécimale codée
hex_string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

# Conversion en octets bruts
ciphertext = bytes.fromhex(hex_string)

# Décryptage
key, decrypted_message = decrypt_single_byte_xor(ciphertext)

# Affichage des résultats
print(f"Clé : {key}")
print(
    f"Message déchiffré : {decrypted_message.decode('utf-8', errors='replace')}")
