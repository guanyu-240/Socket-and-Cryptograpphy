PROGRAM DESCRIPTION:
Simple program for file encryption and decryption.
Using AES for file encryption and decryption.
Using RSA for AES key encryption and decryption.

LOGIC AND PROCESSES:
Encrypt:
1. Read the RSA key files and the file to encrypt
2. Generate AES key
3. Sign the file using RSA private key of sender
4. Encrypt the AES key using RSA public key of receiver
5. Encrypt the whole file using AES key
6. Output file constructions: 
       size of signature: 4 bytes:
       size of encrypted AES key: 4 bytes:
       signature
       encrypted key
       encrypted file content
Decrypt:
1. Read the RSA key files and the file to decrypt
2. Get the size of signature and size of encrypted AES key from the first 8 bytes
3. Read the signature and encrypted AES key based on step 2
4. Decrypt AES key
5. Decrypt the file
6. Verify the signature of the file, if fails, program will exit without outputing.

Program Supports: 
Any type of file less than 100MB
Any size of valid RSA private key and public key. But key files should be in 'der' format


SOURCE CODES:
bin/


SAMPLE KEY FILES:
keys/
s_pri_key.der: sender private key
s_pub_key.der: sender public key
r_pri_key.der: receiver private key
r_pub_key.der: receiver public key


OS RESTRICTION:
Linux(Bash shell is recommended)
JDK RESTRICTION:
JAVA JDK 6/7
JRE RESTRICTION:
JAVA JRE 6/7


COMPILING INSTRUCTION:
On the directory including this README file, type 'make' to complete
the compilation process. After the process, .class files are outputed 
into 'bin' directory. Also, there is a fcrypt.jar file inside the current
directory


EXECUTING OPTIONS:
(1) In the current directory:
Encrypt:
        java -jar fcrypt.jar <receiver_public_key_file> <sender_private_key_file> <input_file> <output_cipher_file>
Decrypt: 
        java -jar fcrypt.jar <receiver_private_key_file> <sender_public_key_file> <input_cypher_file> <output_file>

(2) Step into 'bin' directory:
Encrypt:
        java fcrypt <receiver_public_key_file> <sender_private_key_file> <input_file> <output_cipher_file>
Decrypt:
        java fcrypt <receiver_private_key_file> <sender_public_key_file> <input_cypher_file> <output_file>

