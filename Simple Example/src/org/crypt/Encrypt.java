/* Encrypt - Object of encryption 
 */
package org.crypt;

import java.io.*;
import java.nio.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

public class Encrypt{
	private Key aesKey;		
	private PublicKey rsaPubKey;
	private PrivateKey rsaPriKey;
	private KeyFactory kf;		// key factory for generating RSA public and private key
	private FileInputStream inPubKeyFile;			
	private FileInputStream inPriKeyFile;
	private File fileToEncrypt;
	private FileInputStream inFile;	
	private DataInputStream inStream;
	private DataOutputStream out;
	private byte[] pubKeyBytes;
	private byte[] priKeyBytes;
	private byte[] aesKeyBytes;
	private byte[] sigBytes;
	private byte[] encryptedKey;
	private byte[] fileBytes;
	private Signature rsaSig;	
	private Cipher aesCipher;
	private Cipher rsaCipher;	
	public final long MAX_FILE_SIZE = 100000000;

	private static byte[] intToBytes(int x){
		ByteBuffer buf = ByteBuffer.allocate(4);
		buf.putInt(x);
		return buf.array();
	}

	public Encrypt(String pubKeyFile, String priKeyFile, String filename) throws Exception{
		// initialize file streams for reading key files and the file to encrypt
		inPubKeyFile = new FileInputStream(new File(pubKeyFile));
		inPriKeyFile = new FileInputStream(new File(priKeyFile));
		fileToEncrypt = new File(filename);
		if (fileToEncrypt.length() > MAX_FILE_SIZE){
			System.out.println("File too large. Please specify a file smaller than 100000KB!");
			System.exit(-1);
		}
        inFile = new FileInputStream(fileToEncrypt);
        inStream = new DataInputStream(inFile);
		pubKeyBytes = new byte[inPubKeyFile.available()];
		priKeyBytes = new byte[inPriKeyFile.available()];
		fileBytes = new byte[(int)fileToEncrypt.length()];
		inStream.readFully(fileBytes);
		// read the public key and private key to byte arrays
		inPubKeyFile.read(pubKeyBytes);
		inPriKeyFile.read(priKeyBytes);
		// convert bytes arrays describing pub key and private key to Publickey and Private Key
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyBytes);
		PKCS8EncodedKeySpec priKeySpec = new PKCS8EncodedKeySpec(priKeyBytes);
		kf = KeyFactory.getInstance("RSA");
		rsaPubKey = kf.generatePublic(pubKeySpec);
		rsaPriKey = kf.generatePrivate(priKeySpec);
		rsaSig = Signature.getInstance("SHA1withRSA");
		// generate AES key
		aesKey = KeyGenerator.getInstance("AES").generateKey();
		aesKeyBytes = aesKey.getEncoded();
		aesCipher = Cipher.getInstance("AES");
		aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
		rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		rsaCipher.init(Cipher.ENCRYPT_MODE, rsaPubKey);
	}	
	
	// sign the file using RSA private key of sender
	private void sign() throws Exception{
		rsaSig.initSign(rsaPriKey);
		rsaSig.update(fileBytes);
		sigBytes = rsaSig.sign();
		System.out.println("File successfully signed!");
	}
	
	// encrypt the AES key using RSA public key of receiver
	private void encryptKey() throws Exception{
		encryptedKey = rsaCipher.doFinal(aesKeyBytes);
	}

	// encrypt the whole file using AES key
	public void encrypt_file(String output) throws Exception{
		sign();
		encryptKey();
		long file_size = fileToEncrypt.length();
		out = new DataOutputStream(new FileOutputStream(output));
		// put the size of signature and encrypted key in the beginning
		out.write(intToBytes(sigBytes.length));
		out.write(intToBytes(encryptedKey.length));
		// write the signature and encrypted key
		out.write(sigBytes);
		out.write(encryptedKey);
		byte[] cypher_text = aesCipher.doFinal(fileBytes);
		// write the cipher text
		out.write(cypher_text);
		out.close();
		System.out.println("File successfully encrypted!");
	}

	// close all input streams
	public void closeAll() throws IOException{
		inPubKeyFile.close();
		inPriKeyFile.close();
		inFile.close();
		inStream.close();
	}
}
