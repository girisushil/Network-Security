import KeyPairs_Generation
import PKDA
import random
import gmpy2
import datetime


class Client:

    def __init__(self, client_id, pkda, public, private):
        self.client_id = client_id
        self.pkda = pkda  # connection of client with the pdka
        self.generated_public, self.generated_private = public, private  # for stoering generated key pairs of a client [public key, private key]

    def get_public_cluent_key(self):
        return self.generated_public

    def get_private_cluent_key(self):
        return self.generated_private


    def decrypt(self, value, key):
        if key == 'type' or key == 'sender' or key == 'receiver' or key == 'client_id' or key == 'timeStamp':
            res = []
            for i in range(0, len(value)):
                res.append(((value[i]) ** self.pkda.res[0][0]) % self.pkda.res[0][1])
            r = ""
            for val in res:
                r = r + chr(val)
            return r
        else:
            if key == 'nonce' or key == 'encrypted_public_key':
                res2 = ((int(value) ** self.pkda.res[0][0]) % self.pkda.res[0][1])
                return res2
            else:
                return value

    def Response_Decrypted(self, response):
        nelst = []
        for i in response:
            if i == 'encrypted_public_key':
                pub = response[i][0]
                whole = response[i][1]
                r = self.decrypt(pub, 'encrypted_public_key')
                e = self.decrypt(whole, 'encrypted_public_key')
                nelst.append(r)
                nelst.append(e)
                response[i] = nelst
            else:
                temp = self.decrypt(response[i], i)
                response[i] = temp
        return response

    def Authentication(self, r):

        time_val = str(datetime.datetime.now())[:19]
        signature = r['signature']
        decrypt_sig = [str(x) for x in signature]
        res = [int(x) for x in decrypt_sig]
        plain = [gmpy2.powmod(k, self.pkda.res[0][0], self.pkda.res[0][1]) for k in res]
        res2 = [int(x) for x in plain]
        decrypted_Signature = bytes(res2)
        print('\n')
        print("Hash of the Decrypted Signature :", decrypted_Signature)
        if r['hash'] == decrypted_Signature and r['duration'] > time_val:
            return True
        else:
            return False

    def send_req_to_pkda(self, other_client_id):
        nonce = random.randint(0, 2 ** 32 - 1)
        time_val = str(datetime.datetime.now())[:19]
        duration = list(time_val)
        duration[14] = str(int(duration[14]) + 2)
        duration = ''.join(duration)
        print("Duration :", duration)
        print("Time :", (str(time_val)))

        request = {
            'type': 'public_key_request',
            'sender': self.client_id,
            'receiver': 'pkda',
            'client_id': other_client_id,
            'nonce': nonce,
            'timeStamp': time_val,
            'duration': duration
        }
        ans_from_pkda = self.pkda.handle_request(request)
        return ans_from_pkda

    def encrypt_request(self, value, key, other_Client_public_key):
        res = []
        if key == 'type' or key == 'sender' or key == 'receiver' or key == 'client_id':
            test_list = [value]
            r = [ord(ele) for sub in test_list for ele in sub]
            for i in range(0, len(r)):
                res.append(((r[i]) ** other_Client_public_key[0]) % other_Client_public_key[1])
            return res
        else:
            res2 = ""
            if (key == 'nonce'):
                res2 += str((value ** other_Client_public_key[0]) % other_Client_public_key[1])
                return res2
            else:
                return value

    def Communicate_otherClient(self, other_Client_public_key, other_client_id, nonce1):

        request = {
            'type': 'request_to_other_client',
            'sender': self.client_id,
            'receiver': 'B',
            'client_id': other_client_id,
            'nonce': nonce1,
        }
        for i in request:
            temp = self.encrypt_request(request[i], i, other_Client_public_key)
            request[i] = temp
        return request

    def encrypt_request_for_nonces(self, value, key, other_Client_public_key):
        res = []
        if key == 'type' or key == 'sender' or key == 'receiver' or key == 'client_id':
            test_list = [value]
            r = [ord(ele) for sub in test_list for ele in sub]
            for i in range(0, len(r)):
                res.append(((r[i]) ** other_Client_public_key[0]) % other_Client_public_key[1])
            return res
        else:
            res2 = ""
            if key == 'nonce1' or key == 'nonce2':
                res2 += str((value ** other_Client_public_key[0]) % other_Client_public_key[1])
                return res2
            else:
                return value

    def send_Message_to_other(self, other_Client_public_key, other_client_id, nonce1, nonce2, choice1):
        if choice1:
            request_2 = {
                'type': 'request_to_other_client',
                'sender': self.client_id,
                'receiver': 'A',
                'client_id': other_client_id,
                'nonce1': nonce1,
                'nonce2': nonce2,
            }
            for i in request_2:
                temp = self.encrypt_request_for_nonces(request_2[i], i, other_Client_public_key)
                request_2[i] = temp
            return request_2
        else:
            request_3 = {
                'type': 'request_to_other_client',
                'sender': self.client_id,
                'receiver': 'B',
                'client_id': other_client_id,
                'nonce2': nonce2,
            }
            for i in request_3:
                temp = self.encrypt_request_for_nonces(request_3[i], i, other_Client_public_key)
                request_3[i] = temp
            return request_3


def testcases(B, A, Message, Response):
    message = [Message]
    repsonse = [Response]
    res = [ord(ele) for sub in message for ele in sub]
    print('\n')
    print("Sending the Message to B")
    print("Message to be sent : ", message[0])
    en_Message = []
    dec_Message = []
    for i in range(0, len(res)):
        en_Message.append(((res[i] ** B.get_public_cluent_key()[0]) % B.get_public_cluent_key()[1]))
    print("Encrypted Message ", en_Message)
    print('\n')
    print("B's Decryption of  the Message :")
    for i in range(0, len(en_Message)):
        dec_Message.append(((en_Message[i] ** B.get_private_cluent_key()[0]) % B.get_private_cluent_key()[1]))
    print("Decrypted Message in ascii", dec_Message)
    recived_Message = ""
    for val in dec_Message:
        recived_Message += chr(val)
    print("Decrypted Message :", recived_Message)


# part for repsonding to the received request or statement
    print("B will respond to A that he recieved the Message.")
    print("B sends message to A .")

    res2 = [ord(ele) for sub in repsonse for ele in sub]
    print("Sending the Message to A ....")
    print("Message to be sent : ", repsonse)
    en_message = []
    dec_message = []
    for i in range(0, len(res2)):
        en_message.append(((res2[i] ** A.get_public_cluent_key()[0]) % A.get_public_cluent_key()[1]))
    print("Encrypted Message ", en_message)
    print('\n')
    print("A's Decryption of the Message :")
    for i in range(0, len(en_message)):
        dec_message.append(((en_message[i] ** A.get_private_cluent_key()[0]) % A.get_private_cluent_key()[1]))
    recived_Message = ""
    for val in dec_message:
        recived_Message += chr(val)
    print("Decrypted Message :", recived_Message)

    print('\n')
    print('\n\n')


if __name__ == "__main__":

    print("A's Key Pair Generation: ")
    a_public, a_private = KeyPairs_Generation.generate_keypair(1)
    print("A's Public Keys:", a_public)
    print("A's Private Keys:", a_private)
    print('\n')

    print("B's Key Pair Generation: ")
    b_public, b_private = KeyPairs_Generation.generate_keypair(1)
    print("B's Public Keys:", b_public)
    print("B's Private Keys:", b_private)

    print("PKDA Key Pair Generation: ")
    pkda = PKDA.PKDA()
    pkda.generate_pkda_keys()
    pkda.add_client('A', a_public)
    pkda.add_client('B', b_public)

    A_client = Client('A', pkda, a_public, a_private)
    B_client = Client('B', pkda, b_public, b_private)

    print('\n')
    print("Initiator A own Public-Key Details From PKDA", pkda.Owner_details_from_pkda('A'))
    print('\n')
    print("Initiator B's Public-Key Details From PKDA", pkda.Owner_details_from_pkda('B'))
    print('\n')
    print('\n\n')

    print("1 : Intiatiator A Request to PKDA for B's public key")
    r = A_client.send_req_to_pkda('B')
    print('\n')
    print(" 2 :Encrypted Response From PKDA using  private Key to A.........", r, end='\n')
    Verify_Encrypted_response = A_client.Response_Decrypted(r)
    print('\n')
    print("3: Decrypted Response By A using public  Key of pkda.........")
    print(Verify_Encrypted_response)
    print('\n')
    print("Verify Signature By Alice.........")
    verify = A_client.Authentication(r)
    if (verify == True):
        print("Message is authentic")
    else:
        print("Tampered Message")

    print('\n')

    decrypt1 = (Verify_Encrypted_response['encrypted_public_key'])
    print("Decrypted Public Key pair of B's :", decrypt1)
    print('\n')
    print('\n\n')
    print('\n')

    print(
        '4: Inititiator A Sends to B the  Messaage of establishing connection by encrypting Nonce and  client id using B public Key after getting from pkda...')

    nonce1 = random.randint(0, 2 ** 32 - 1)
    request = A_client.Communicate_otherClient(decrypt1, 'B', nonce1)

    print("Encrypted request from A to B :", request)

    print('\n')
    print('\n\n')

    print('\n')
    print("5 :Now B Request to PKDA for A's public key")
    r2 = B_client.send_req_to_pkda('A')
    print("Encrypted Response From PKDA using his private Key to B.........", r2, end='\n')
    Verify_Encrypted_response_2 = B_client.Response_Decrypted(r2)
    print('\n')
    print("Decrypted Response By B using public Keys of pkda.........")
    print(Verify_Encrypted_response_2)
    print('\n')

    print("Verify Signature By Bob.........")
    verify = B_client.Authentication(Verify_Encrypted_response_2)
    if (verify == True):
        print("Message Authentic")
    else:
        print("Tampered Message")

    print('\n')
    decrypt2 = (Verify_Encrypted_response_2['encrypted_public_key'])
    print("Decrypted Public Key pair of A :", decrypt2)
    print('\n\n')
    print('\n')

    print(
        "6 : After Receiving Public Key of Alice from PKDA,B will send the nonce N1 and N2 for confirming the establishment"
        "of connection by encrypting nonces using public key of A.")
    print('\n')

    nonce2 = random.randint(0, 2 ** 32 - 1)
    En_req_B = B_client.send_Message_to_other(decrypt2, 'A', nonce1, nonce2,1)

    print("Encrypted Request from B to A for establishment of connection :", En_req_B)

    print('\n')
    print('\n\n')
    print('\n')

    print(
    "7:  A received the nonces and replies back with Nonce 2 to B which confirms establishment of connection")

    encrypted_request_A_Nonce_2 = A_client.send_Message_to_other(decrypt1, 'B',"",nonce2,0)

    print("Connection Secured and can be used for further communication after A sends nonce 2")
    print(encrypted_request_A_Nonce_2)

    print('\n')
    print('\n\n')

    print('\n')
    print(
    " TestCases run by Esthablishing a verified medium of communciation by sending Messages from Initiator A to B:")

    testcases(B_client, A_client, 'Hi1', 'Got-it1')
    print(" Similarly Initiator A Send 2nd Message to Initiator B  :")
    testcases(B_client, A_client, 'Hi2', 'Got-it2')
    print(" Similarly Initiator A Send 3rd Message to B :")
    testcases(B_client, A_client, 'Hi3', 'Got-it3')
