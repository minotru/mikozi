# Simon Karasik, mikozi, lab 1, v. 4

ALPHABET = 'АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ'
ALPHABET_LEN = len(ALPHABET)


def char_to_code(char: str) -> int:
    return ord(char) - ord('А')


def code_to_char(code: int) -> str:
    return chr(code + ord('А'))


def vigenere_encrypt(plain_text: str, key: str) -> str:
    cypher_text = ''
    for ind, char in enumerate(plain_text):
        key_char_ind = ALPHABET.index(key[ind % len(key)])
        char_ind = ALPHABET.index(char)
        cypher_char = ALPHABET[(char_ind + key_char_ind) % len(ALPHABET)]
        cypher_text += cypher_char
    return cypher_text


def vigenere_decrypt(cypher_text: str, key: str) -> str:
    plain_text = ''
    for ind, char in enumerate(cypher_text):
        key_char_ind = ALPHABET.index(key[ind % len(key)])
        char_ind = ALPHABET.index(char)
        plain_char = ALPHABET[(char_ind - key_char_ind) % len(ALPHABET)]
        plain_text += plain_char
    return plain_text


def matrix_det(matrix_2x2) -> int:
    return matrix_2x2[0][0] * matrix_2x2[1][1] - matrix_2x2[0][1] * matrix_2x2[1][0]


def hill_check_args(text: str, key_matrix_2x2):
    if matrix_det(key_matrix_2x2) == 0:
        raise ValueError('Key has null determinant')
    if len(text) % 2 != 0:
        raise ValueError('Length of text must be divisible by 2')


# extended Euclidean algorithm
def egcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y


def modinv(a: int, m: int) -> int:
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError('modular inverse does not exist')
    else:
        return x % m


def matrix_inverse(matrix_2x2):
    det = matrix_det(matrix_2x2)
    inv_det = modinv(det, len(ALPHABET))
    m_00 = (inv_det * matrix_2x2[1][1]) % len(ALPHABET)
    m_01 = (inv_det * -matrix_2x2[0][1]) % len(ALPHABET)
    m_10 = (inv_det * -matrix_2x2[1][0]) % len(ALPHABET)
    m_11 = (inv_det * matrix_2x2[0][0]) % len(ALPHABET)
    return [[m_00, m_01], [m_10, m_11]]


def hill_encrypt(plain_text: str, key_matrix_2x2) -> str:
    hill_check_args(plain_text, key_matrix_2x2)

    plain_vector = list(map(char_to_code, plain_text))
    cypher_vector = []
    for k in range(len(plain_vector) // 2):
        code_1, code_2 = plain_vector[2*k], plain_vector[2*k + 1]
        for i in range(2):
            cypher_vector.append((key_matrix_2x2[i][0]*code_1 + key_matrix_2x2[i][1]*code_2) % len(ALPHABET))

    return ''.join(map(code_to_char, cypher_vector))


def hill_decrypt(cypher_text: str, key_matrix_2x2) -> str:
    hill_check_args(cypher_text, key_matrix_2x2)

    cypher_vector = list(map(char_to_code, cypher_text))
    inv_key = matrix_inverse(key_matrix_2x2)
    plain_vector = []
    for k in range(len(cypher_vector) // 2):
        code_1, code_2 = cypher_vector[2*k], cypher_vector[2*k + 1]
        for i in range(2):
            plain_vector.append((inv_key[i][0]*code_1 + inv_key[i][1]*code_2) % len(ALPHABET))

    return ''.join(map(code_to_char, plain_vector))


def vigenere_read_data(filename:str):
    input_file = open(filename, 'r', encoding='utf8')
    text, key = input_file.readline().split()
    input_file.close()
    return text, key


def test_vigenere_encrypt():
    plain_text, key = vigenere_read_data('vigenere_encrypt.txt')
    cypher_text = vigenere_encrypt(plain_text, key)
    print('Encrypted text:{}'.format(cypher_text))


def test_vigenere_decrypt():
    cypher_text, key = vigenere_read_data('vigenere_decrypt.txt')
    plain_text = vigenere_decrypt(cypher_text, key)
    print('Decrypted text:{}'.format(plain_text))


def hill_read_data(filename: str):
    input_file = open(filename, 'r', encoding='utf8')
    text = input_file.readline()[0:-1]
    key_matrix = []
    for line in input_file.readlines():
        key_matrix.append(list(map(int, line.split())))
    input_file.close()
    return text, key_matrix


def test_hill_encrypt():
    plain_text, key_matrix = hill_read_data('hill_encrypt.txt')
    cypher_text = hill_encrypt(plain_text, key_matrix)
    print('Encrypted text:{}'.format(cypher_text))


def test_hill_decrypt():
    cypher_text, key_matrix = hill_read_data('hill_decrypt.txt')
    plain_text = hill_decrypt(cypher_text, key_matrix)
    print('Decrypted text:{}'.format(plain_text))


def main():
    print('Encrypt/decrypt tool')
    print('Supports А..Я symbols only.')
    while True:
        print('1. vigenere encrypt: input file "vigenere_encrypt.txt", structure: <plain_text> <key>, output: console')
        print('2. vigenere decrypt: input file "vigenere_decrypt.txt", structure: <cypher_text> <key>, output: console')
        print('3. hill encrypt: input file "hill_encrypt.txt", structure: <plain_text> <2x2_key_matrix by lines>')
        print('4. hill decrypt: input file "hill_encrypt.txt", structure: <plain_text> <2x2_key_matrix by lines>')
        print('0. exit')
        choice = int(input('your choice:->'))
        try:
            if choice == 1:
                test_vigenere_encrypt()
            if choice == 2:
                test_vigenere_decrypt()
            if choice == 3:
                test_hill_encrypt()
            if choice == 4:
                test_hill_decrypt()
            if choice == 0:
                break
        except Exception as e:
            print('Exception:{}'.format(e))

main()
