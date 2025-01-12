def pkcs7_padding(message: bytes, block_size: int) -> bytes:
    """
    Applique le remplissage PKCS#7 à un message pour atteindre une taille multiple de block_size.

    :param message: Le message à remplir (en octets).
    :param block_size: La taille du bloc.
    :return: Le message rempli.
    """
    if block_size <= 0 or block_size > 255:
        raise ValueError(
            "La taille du bloc doit être comprise entre 1 et 255.")

    # Calcul de la taille de remplissage nécessaire
    padding_needed = block_size - (len(message) % block_size)
    # Générer les octets de remplissage
    padding = bytes([padding_needed] * padding_needed)
    # Retourner le message rempli
    return message + padding


# Exemple d'utilisation
if __name__ == "__main__":
    message = b"SOUS-MARIN JAUNE"
    block_size = 20
    padded_message = pkcs7_padding(message, block_size)
    print(f"Message rempli : {padded_message}")
