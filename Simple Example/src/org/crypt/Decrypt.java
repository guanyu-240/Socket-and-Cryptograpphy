/* Decrypt - Object of decryption
 */

package org.crypt;

import java.io.*;
import java.nio.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

public class Decrypt{
	private SecretKeySpec aesKey;
	private PublicKey rsaPubKey;
	private PrivateKey rsaPriKey;
	private KeyFactory kf;
	private FileInputStream inPubKeyFile;
	private FileInputStream inPriKeyFile;
	private FileInputStream fileToDecrypt;
	private DataOutputStream out;
	private byte[] pubKeyBytes;
	private byte[] priKeyBytes;
	private byte[] aesKeyBytes;
	private byte[] sigBytes;
	private byte[] encryptedKey;
	private byte[] cipherBytes;
	private byte[] fileBytes; 
	private Signature rsaSig;
	private Cipher aesCipher;
	private Cipher rsaCipher;
	private final long BLK_SIZE = 1024;

	// function for converting bytes array to int
	private static int bytesToInt(byte[] arr){
		ByteBuffer buf = ByteBuffer.wrap(arr);
		return buf.getInt();
	}
	
	// decrypt AES key and load it
	private void loadAESKey() throws Exception{
		aesKeyBytes = rsaCipher.doFinal(encryptedKey);
		aesKey = new SecretKeySpec(aesKeyBytes, "AES");
	}

	public Decrypt(String pubKeyFile, String priKeyFile, String file) throws Exception{
		// initialize the file input streams for key files and the file to decrypt
		inPubKeyFile = new FileInputStream(new File(pubKeyFile));
		inPriKeyFile = new FileInputStream(new File(priKeyFile));
		fileToDecrypt = new FileInputStream(new File(file));
		pubKeyBytes = new byte[inPubKeyFile.available()];
		priKeyBytes = new byte[inPriKeyFile.available()];
		// get the size of signature and encrypted key
		byte[] sizeSig = new byte[4];
		byte[] sizeEncKey = new byte[4];
		fileToDecrypt.read(sizeSig);
		fileToDecrypt.read(sizeEncKey);
		sigBytes = new byte[bytesToInt(sizeSig)];
		encryptedKey = new byte[bytesToInt(sizeEncKey)];
		// read key files and the file to decrypt
		inPubKeyFile.read(pubKeyBytes);
		inPriKeyFile.read(priKeyBytes);
		fileToDecrypt.read(sigBytes);
		fileToDecrypt.read(encryptedKey);
		cipherBytes = new byte[fileToDecrypt.available()];
		fileToDecrypt.read(cipherBytes);
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyBytes);
		PKCS8EncodedKeySpec priKeySpec = new PKCS8EncodedKeySpec(priKeyBytes);
		kf = KeyFactory.getInstance("RSA");
		rsaPubKey = kf.generatePublic(pubKeySpec);
		rsaPriKey = kf.generatePrivate(priKeySpec);
		rsaSig = Signature.getInstance("SHA1withRSA");
		rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		rsaCipher.init(Cipher.DECRYPT_MODE, rsaPriKey);
		// decrypt the AES key
		loadAESKey();
		aesCipher = Cipher.getInstance("AES");
		aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
	}	

	// verify the signature
	private boolean verify_sig(byte[] text) throws Exception{
		rsaSig.initVerify(rsaPubKey);
		rsaSig.update(text);
		return rsaSig.verify(sigBytes);
	}
	
	public void decrypt_file(String output) throws Exception{
		long file_size = fileToDecrypt.available();
		out = new DataOutputStream(new FileOutputStream(output));
		fileToDecrypt.read(cipherBytes);
		// decrypt the file
		byte[] text = aesCipher.doFinal(cipherBytes);
		// verify the signature, if false, no write 
		boolean verify = verify_sig(text);
		if (!verify){
			System.out.println("Signature verification failed!");
			out.close();
			System.exit(-1);
		}
		System.out.println("Signature verification passed!");
		out.write(text);
		out.close();
		System.out.println("File successfully decrypted!");
	}
	
	// close all input streams
	public void closeAll() throws Exception{
		inPubKeyFile.close();
		inPriKeyFile.close();
		fileToDecrypt.close();
	}
}
