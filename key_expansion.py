import S_Boxes

def Substitution(word):

    # subsitute hexadecimal alphaets "a-f"
    sWord = ()
    for i in range(4):
        if word[i][0].isdigit() == False:
            row = ord(word[i][0]) - 86
        else:
            row = int(word[i][0])+1

        if word[i][1].isdigit() == False:
            col = ord(word[i][1]) - 86
        else:
            col = int(word[i][1])+1
        piecevalue = hex(S_Boxes.s_box[row-1][col-1])
        piecevalue = piecevalue[2:]
        if len(piecevalue) != 2:
            piecevalue = '0' + piecevalue
        sWord = (*sWord, piecevalue)

    return ''.join(sWord)


def bitwiseXoring(hex1, hex2):
    # Convert to binary and xor it and  cut the prefix value return hex value.

    b1 = bin(int(str(hex1), 16))
    b2 = bin(int(str(hex2), 16))

    xord = int(b1, 2) ^ int(b2, 2)

    res = hex(xord)[2:]

    if len(res) != 8:
        res = '0' + res

    return res


def keyExpansion_algo(key):
    # doing key expansion
    w = [()]*44

    for i in range(4):
        w[i] = (key[4*i], key[4*i+1], key[4*i+2], key[4*i+3])

    for i in range(4, 44):
        temp = w[i-1]
        word = w[i-4]

        if i % 4 == 0:
            rotateWord = temp[1:] + temp[:1]
            subword = Substitution(rotateWord)
            index = int(i/4)
            rconstant = S_Boxes.r_const_table[index]
            temp = bitwiseXoring(subword, hex(rconstant)[2:])

        word = ''.join(word)
        temp = ''.join(temp)

        xorvalue = bitwiseXoring(word, temp)
        w[i] = (xorvalue[:2], xorvalue[2:4], xorvalue[4:6], xorvalue[6:8])
    res = []
    st =""
    count =0
    for i in range(len(w)):
        st+=w[i][0] + w[i][1] + w[i][2] + w[i][3]
        count+=1
        if(count == 4):
            res.append(st)
            count =0
            st=""
    return res

        


