import base64
from itertools import combinations

# Fonction pour calculer la distance de Hamming


def hamming_distance(s1, s2):
    assert len(s1) == len(s2), "Les chaînes doivent avoir la même longueur"
    return sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(s1, s2))

# Fonction pour deviner la taille probable de la clé


def guess_keysize(ciphertext, min_keysize=2, max_keysize=40):
    distances = []
    for keysize in range(min_keysize, max_keysize + 1):
        chunks = [ciphertext[i:i + keysize]
                  for i in range(0, len(ciphertext), keysize)]
        if len(chunks) < 2:
            continue
        pairs = list(combinations(chunks[:4], 2))
        avg_distance = sum(hamming_distance(
            p[0], p[1]) / keysize for p in pairs) / len(pairs)
        distances.append((keysize, avg_distance))
    return sorted(distances, key=lambda x: x[1])

# Fonction pour appliquer le XOR répétitif


def repeating_key_xor(plaintext, key):
    ciphertext = bytearray()
    key_length = len(key)
    for i in range(len(plaintext)):
        ciphertext.append(plaintext[i] ^ key[i % key_length])
    return bytes(ciphertext)


# Fonction pour calculer le score d'un texte basé sur les fréquences en anglais
english_frequencies = {
    'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253, 'e': 12.702,
    'f': 2.228, 'g': 2.015, 'h': 6.094, 'i': 6.966, 'j': 0.153,
    'k': 0.772, 'l': 4.025, 'm': 2.406, 'n': 6.749, 'o': 7.507,
    'p': 1.929, 'q': 0.095, 'r': 5.987, 's': 6.327, 't': 9.056,
    'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150, 'y': 1.974, 'z': 0.074,
    ' ': 13.0
}


def score_text(text):
    return sum(english_frequencies.get(chr(byte).lower(), 0) for byte in text)

# Fonction pour déchiffrer un XOR à un seul caractère


def decrypt_single_byte_xor(ciphertext):
    best_score = 0
    best_result = None
    best_key = None

    for key in range(256):
        plaintext = bytes([byte ^ key for byte in ciphertext])
        score = score_text(plaintext)
        if score > best_score:
            best_score = score
            best_result = plaintext
            best_key = key

    return best_key, best_result

# Fonction principale pour déchiffrer un XOR à clé répétée


def break_repeating_key_xor(ciphertext):
    probable_keysizes = guess_keysize(ciphertext)[:3]
    best_key = None
    best_plaintext = None

    for keysize, _ in probable_keysizes:
        blocks = [ciphertext[i:i + keysize]
                  for i in range(0, len(ciphertext), keysize)]
        transposed_blocks = [
            bytes([block[i] for block in blocks if i < len(block)]) for i in range(keysize)]
        key = bytearray()

        for block in transposed_blocks:
            key_byte, _ = decrypt_single_byte_xor(block)
            key.append(key_byte)

        plaintext = repeating_key_xor(ciphertext, key)
        if best_plaintext is None or score_text(plaintext) > score_text(best_plaintext):
            best_plaintext = plaintext
            best_key = key

    return best_key, best_plaintext


# Charger le fichier chiffré et décodé en Base64
with open('C:\\Users\\arpin\\OneDrive\\Bureau\\chall crypto\\level1\\text.txt', 'r') as file:
    ciphertext = base64.b64decode(file.read())

# Déchiffrement
key, plaintext = break_repeating_key_xor(ciphertext)

# Affichage des résultats
print(f"Clé trouvée : {key.decode('utf-8', errors='replace')}")
print(f"Texte déchiffré : {plaintext.decode('utf-8', errors='replace')}")
