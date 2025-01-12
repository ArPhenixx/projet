input_1 = "1c0111001f010100061a024b53535009181c"
input_2 = "686974207468652062756c6c277320657965"

# convert to decimal
decimal_1 = int(input_1, 16)
decimal_2 = int(input_2, 16)


# XOR the two decimals
decimal_result = decimal_1 ^ decimal_2

# convert the to decimal
hex_result = f"{decimal_result:x}"

print(hex_result)
