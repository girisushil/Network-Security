import secrets
import S_Boxes
from key_expansion import keyExpansion_algo


def substitution(mat):
    # Substitute each byte in the input matrix using  S-Box.
    sub_mat = mat.copy()
    for i in range(4):
        for j in range(4):
            r = mat[i][j] // 0x10
            c = mat[i][j] % 0x10
            sub_mat[i][j] = S_Boxes.s_box[r][c]
    return sub_mat


def inverse_substitution(mat):
    # Substitute each byte in the input matrix using  Inverse S-Box.
    sub_mat = mat.copy()
    for i in range(4):
        for j in range(4):
            r = mat[i][j] // 0x10
            c = mat[i][j] % 0x10
            sub_mat[i][j] = S_Boxes.inverse_s_box[r][c]
    return sub_mat


def circular_shift_array(arr, shift, ch):
    # Performs a circular shift on a 1D array by a specific shift amount and depending upon choices.
    n = len(arr)
    shift %= n  # Ensure shift is within the range of array length
    if ch == 0:
        return arr[shift:] + arr[:shift]
    else:
        return arr[-shift:] + arr[:-shift]


def shift_rows(mat):
    shifted_mat = mat.copy()
    for i in range(4):
        arr = shifted_mat[i]
        shifted_mat[i] = circular_shift_array(arr, i, 0)
    return shifted_mat


def inv_shift_rows(mat):
    shifted_mat = mat.copy()
    for i in range(4):
        arr = shifted_mat[i]
        shifted_mat[i] = circular_shift_array(arr, i, 1)
    return shifted_mat


def convert_to_starting_matrix(plaintext):
    # Takes in a 16 byte hexadecimal string and returns a 4x4 state matrix.

    mat = [[0, 0, 0, 0],
           [0, 0, 0, 0],
           [0, 0, 0, 0],
           [0, 0, 0, 0]]
    for i in range(4):
        for j in range(4):
            mat[j][i] = int(plaintext[8 * i + 2 * j: 8 * i + 2 * (j + 1)], 16)
    return mat


def convert_mat_to_str(mat):
    # Converts a state matrix of decimal values to a hexadecimal representation and joins them into a single string.
    str_arr = []
    for i in range(16):
        str_arr.append(0)

    for r in range(4):
        for c in range(4):
            str_arr[r + 4 * c] = mat[r][c]
    res = ''.join([hex(x)[2:].zfill(2) for x in str_arr])
    return res

def mix_columns(org_mat):

    # Performs the MixColumns step in AES on the input matrix.
    new_mat = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
    for c in range(4):
        word_c = [org_mat[i][c] for i in range(4)]
        s0 = galois_mult(word_c[0], 2) ^ galois_mult(word_c[1], 3) ^ word_c[2] ^ word_c[3]
        s1 = word_c[0] ^ galois_mult(word_c[1], 2) ^ galois_mult(word_c[2], 3) ^ word_c[3]
        s2 = word_c[0] ^ word_c[1] ^ galois_mult(word_c[2], 2) ^ galois_mult(word_c[3], 3)
        s3 = galois_mult(word_c[0], 3) ^ word_c[1] ^ word_c[2] ^ galois_mult(word_c[3], 2)
        new_word_c = [s0, s1, s2, s3]
        for i in range(4):
            new_mat[i][c] = new_word_c[i]
    return new_mat

def inverse_mix_columns(org_mat):
    # Performs the Inverse MixColumns step in AES on the input matrix.
    new_mat = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
    for c in range(4):
        word_c = [org_mat[i][c] for i in range(4)]
        s0 = galois_mult(word_c[0], 0xe) ^ galois_mult(word_c[1], 0xb) ^ galois_mult(word_c[2], 0xd) ^ galois_mult(word_c[3], 0x9)
        s1 = galois_mult(word_c[0], 0x9) ^ galois_mult(word_c[1], 0xe) ^ galois_mult(word_c[2], 0xb) ^ galois_mult(word_c[3], 0xd)
        s2 = galois_mult(word_c[0], 0xd) ^ galois_mult(word_c[1], 0x9) ^ galois_mult(word_c[2], 0xe) ^ galois_mult(word_c[3], 0xb)
        s3 = galois_mult(word_c[0], 0xb) ^ galois_mult(word_c[1], 0xd) ^ galois_mult(word_c[2], 0x9) ^ galois_mult(word_c[3], 0xe)
        new_word_c = [s0, s1, s2, s3]
        for i in range(4):
            new_mat[i][c] = new_word_c[i]
    return new_mat

def galois_mult(num, mult=2):

    #Performs multiplication of two numbers  in GF(2^8)

    res = 0xff & (num << 1)
    if mult == 1:
        return num
    if mult == 2:
        if num < 128: return res
        else: return res ^ 0x1b
    if mult == 3:
        return num ^ galois_mult(num, 2)
    if mult == 9:
        return num ^ galois_mult(galois_mult(galois_mult(num)))
    if mult == 11:
        return num ^ galois_mult(galois_mult(galois_mult(num))) ^ galois_mult(num)
    if mult == 13:
        return num ^ galois_mult(galois_mult(galois_mult(num))) ^ galois_mult(galois_mult(num))
    if mult == 14:
        return galois_mult(galois_mult(galois_mult(num))) ^ galois_mult(galois_mult(num)) ^ galois_mult(num)
    else: raise Exception("The mult can only be 2, 3, 9, 11, 13, and 14")



def add_round_key(mat, key_string):
    key = convert_to_starting_matrix(key_string)
    new_state = mat.copy()
    for r in range(4):
        for c in range(4):
            new_state[r][c] = mat[r][c] ^ key[r][c]
    return new_state


def AES_Encrption(plain_text, master_key):
    s = convert_to_starting_matrix(plain_text)
    key = []
    for i in range(0, len(master_key) - 1):
        if (i % 2 == 0):
            key.append(master_key[i:i + 2])
    keys = keyExpansion_algo(key)
    s = add_round_key(s, keys[0])
    print("0", convert_mat_to_str(s))
    r1 = ""
    r9 = ""
    for i in range(1, 11):

        if i == 10:  # for not doing matmul at last round so taking care of this important step
            s = substitution(s)
            s = shift_rows(s)
            s = add_round_key(s, keys[i])
        else:
            s = substitution(s)
            s = shift_rows(s)
            s = mix_columns(s)
            s = add_round_key(s, keys[i])
        if i == 1:
            e1 = s.copy()
            r1 = convert_mat_to_str(e1)
        if i == 9:
            e9 = s.copy()
            r9 = convert_mat_to_str(e9)



        print(i, convert_mat_to_str(s))
    print("\noutput of the 1st encryption round: ", r1)
    print("output of the 9th encryption round: ", r9)
    final_state = s.copy()
    cipher = convert_mat_to_str(final_state)
    return cipher


def AES_Decryption(cipher_text, master_key):
    s = convert_to_starting_matrix(cipher_text)
    key = []
    for i in range(0, len(master_key) - 1):
        if (i % 2 == 0):
            key.append(master_key[i:i + 2])
    keys = keyExpansion_algo(key)
    s = add_round_key(s, keys[10])
    print("0", convert_mat_to_str(s))
    dec_round1 = ""
    dec_round9 = ""
    for i in range(1, 11):
        if i != 10:
            s = inv_shift_rows(s)
            s = inverse_substitution(s)
            if i == 1:
                d1 = s.copy()
                dec_round1 = convert_mat_to_str(d1)
            if i == 9:
                d9 = s.copy()
                dec_round9 = convert_mat_to_str(d9)
            s = add_round_key(s, keys[10 - i])
            s = inverse_mix_columns(s)
        else:
            s = inv_shift_rows(s)
            s = inverse_substitution(s)
            s = add_round_key(s, keys[10 - i])

        print(i, convert_mat_to_str(s))
    print("\noutput of the 1st decryption round: ", dec_round1)
    print("output of the 9th decryption round: ", dec_round9)
    final_state = s.copy()
    decrypted_string = convert_mat_to_str(final_state)
    return decrypted_string


def main():
    pltext = ""
    key = ""

    pltext = secrets.token_hex(16)
    key = secrets.token_hex(16)
    print("\nPlainText: ", pltext)
    print("Key: ", key, "\n")

    print(" AES ENCRYPTION STARTED  \n")
    cipher_text = AES_Encrption(pltext, key)
    print(" AES ENCRYPTION ENDS  \n")
    print("\n\nCipherText: ", cipher_text, end="\n\n")
    print("\n AES DECRYPTION STARTED  \n")
    dectext = AES_Decryption(cipher_text, key)
    print("\n AES DECRYPTION ENDS  \n")
    print("DecryptedText: ", dectext, end="\n\n")
    print("Is plaintext and Decipheredtext same?: ")
    print(pltext == dectext)
    print("Plaintext: ",pltext)
    print("Ciphertext: ",cipher_text)
    print("DecryptedText: ",dectext)


if __name__ == '__main__':
    print("The TEST CASE")
    for i in range(3):
        main()
        print("\n\n\n\n")
        if (i != 2):
            print("The TEST CASES", end="\n\n\n\n")
