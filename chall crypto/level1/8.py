def detect_aes_ecb_mode(file_path):
    """
    Détecte quelle ligne dans un fichier hexadécimal a été chiffrée en mode AES-ECB.

    :param file_path: Chemin du fichier contenant les textes chiffrés en hexadécimal
    :return: Ligne suspectée d'utiliser AES-ECB (sous forme de chaîne hexadécimale)
    """
    def has_repeated_blocks(ciphertext):
        """Vérifie si un texte chiffré contient des blocs répétés."""
        block_size = 16  # Taille de bloc pour AES en bytes
        blocks = [ciphertext[i:i + block_size]
                  for i in range(0, len(ciphertext), block_size)]
        return len(blocks) > len(set(blocks))  # Si des blocs sont répétés

    with open(file_path, 'r') as file:
        for line_number, line in enumerate(file):
            ciphertext = bytes.fromhex(line.strip())  # Conversion en bytes
            if has_repeated_blocks(ciphertext):
                return line.strip(), line_number  # Retourne la ligne suspectée et son numéro

    return None, None  # Aucun texte détecté comme AES-ECB


# Chemin du fichier contenant les textes chiffrés
file_path = 'C:\\Users\\arpin\\OneDrive\\Bureau\\chall crypto\\level1\\8.txt'

# Détection de la ligne chiffrée en mode AES-ECB
suspected_line, line_number = detect_aes_ecb_mode(file_path)

if suspected_line:
    print(f"Ligne suspectée : {suspected_line}")
    print(f"Numéro de ligne : {line_number}")
else:
    print("Aucune ligne chiffrée en mode AES-ECB n'a été détectée.")
