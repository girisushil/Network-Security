import hashlib
import socket
import os
import ssl
from base64 import b64decode
from base64 import b64encode
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

# Load the SSL/TLS certificate of the TSA server
tsa_cert = "/Users/sushilhome/Desktop/A4/cert_s.pem"
client_cert = "/Users/sushilhome/Desktop/A4/cert_c.pem"
client_key = "/Users/sushilhome/Desktop/A4/key_c.pem"

# Connect to the TSA server over an encrypted connection
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_context.load_cert_chain(certfile=client_cert, keyfile=client_key)
ssl_context.load_verify_locations(cafile=tsa_cert)

# Generate a hash of the file to be timestamped
fp = input("Enter Driving license Number : ")
file_hash = hashlib.sha256(fp.encode("utf-8")).hexdigest()

# Connect to the TSA server using SSL/TLS
server_address = ('localhost', 10000)
try:
    with socket.create_connection(server_address) as sock:
        with ssl_context.wrap_socket(sock, server_hostname=server_address[0]) as ssock:
            # Send the file hash to the TSA server
            ssock.sendall(file_hash.encode())

            # Receive the signed timestamp from the TSA server
            timestamp_bytes = ssock.recv(4096)

            # Split the received data into signature, timestamp, and TSA public key
            signature, timestamp, tsa_pub_key, person_info = timestamp_bytes.decode().split(
                ",")
            signature = b64decode(signature)
            timestamp = b64decode(timestamp)
            tsa_pub_key = b64decode(tsa_pub_key)
            person_info = b64decode(person_info)

            print(signature)
            print("\n\n\n")
            print(person_info)

            # Import the TSA public key and use it to decrypt the received signature
            tsa_pub_key_n = RSA.import_key(tsa_pub_key)
            cipher = PKCS1_OAEP.new(tsa_pub_key_n)
            decrypted_signature = cipher.decrypt(signature)

            name, age, city, doi, expiry, DL, valid = person_info.decode('utf-8').split(",")

            # Calculate the hash of the file_hash, timestamp, and TSA public key
            hash_func = SHA256.new()
            data_with_tstamp_pubkey = file_hash.encode() + timestamp + tsa_pub_key + person_info
            hash_func.update(data_with_tstamp_pubkey)
            timestamped_hash = hash_func.digest()

            # Verify the decrypted signature against the calculated hash
            print("\ndecrypted_signature: ", decrypted_signature)
            print("\nhash_to_be_checked:  ", timestamped_hash)

            if decrypted_signature == timestamped_hash:
                print("\nSignature verified.\n\n")
                print("File Hash: ", file_hash.encode())
                print("\nTimestamp: ", timestamp)
                print("\nPublic Key TSA: ", b64encode(tsa_pub_key))
                print("\nSignature: ", b64encode(signature))
            else:
                print("Signature cannot be verified tempered!!!")


                # Save the received data to a file
            print("Correct till here")
            fa = "client_tsa_document.txt"
            with open(fa, 'w') as f:
                f.write(f'File Hash: ')
                f.write(file_hash)
                f.write(os.linesep)
                f.write(f'Timestamp: ')
                f.write(timestamp.decode('utf-8'))
                f.write(os.linesep)
                f.write(f'TSA Public Key: ')
                f.write(tsa_pub_key.decode('utf-8'))
                f.write(os.linesep)
                f.write(f'Signature: ')
                f.write(str(signature))
                f.write(os.linesep)
                f.write(f'Name: ')
                f.write(name)
                f.write(os.linesep)
                f.write(f'Age: ')
                f.write(age)
                f.write(os.linesep)
                f.write(f'City: ')
                f.write(city)
                f.write(os.linesep)
                f.write(f'Date Of Issue: ')
                f.write(doi)
                f.write(os.linesep)
                f.write(f'Expiration DL: ')
                f.write(expiry)
                f.write(os.linesep)
                f.write(f'DL: ')
                f.write(DL)
                f.write(os.linesep)
                f.write(f'Validity Status: ')
                f.write(valid)


except Exception as e:
    print(e)
    print("No server available")
