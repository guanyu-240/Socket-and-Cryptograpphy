package cs6740.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/*
 * Class of RSA encryption, decryption and signature
 */
public class RSACrypt {
	private static FileInputStream inPubKeyFile;			
	private static FileInputStream inPriKeyFile;
	private static KeyFactory kf;
	private PublicKey rsaPubKey;
	private PrivateKey rsaPrivKey;
	private Cipher rsaCipher;
	private Signature rsaSig;
	public PublicKey getRsaPub() {
		return rsaPubKey;
	}
	public void setRsaPub(PublicKey rsaPub) {
		this.rsaPubKey = rsaPub;
	}
	public PrivateKey getRsaPriv() {
		return rsaPrivKey;
	}
	public void setRsaPriv(PrivateKey rsaPriv) {
		this.rsaPrivKey = rsaPriv;
	}
	
	/*
	 * convert RSA key file to RSA public key
	 */
	public static PublicKey file2RSAPublicKey(String pubKeyFile){
		try {
			inPubKeyFile = new FileInputStream(new File(pubKeyFile));
			byte[] pubKeyBytes = new byte[inPubKeyFile.available()];
			inPubKeyFile.read(pubKeyBytes);
			X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyBytes);
			kf = KeyFactory.getInstance("RSA");
			return kf.generatePublic(pubKeySpec);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return null;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	/*
	 * convert RSA key file to RSA private key
	 */
	public static PrivateKey file2RSAPrivateKey(String priKeyFile){
		try {
			inPriKeyFile = new FileInputStream(new File(priKeyFile));
			byte[] priKeyBytes = new byte[inPriKeyFile.available()];
			inPriKeyFile.read(priKeyBytes);
			PKCS8EncodedKeySpec priKeySpec = new PKCS8EncodedKeySpec(priKeyBytes);
			kf = KeyFactory.getInstance("RSA");
			return kf.generatePrivate(priKeySpec);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return null;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	// construct method of the class for RSA encryption and signature verification
	public RSACrypt(PublicKey key){
		try {
			this.rsaPubKey = key;
			rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsaCipher.init(Cipher.ENCRYPT_MODE, rsaPubKey);
			rsaSig = Signature.getInstance("SHA1withRSA");
			rsaSig.initVerify(rsaPubKey);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
	}
	
	// construct method of the class for RSA decryption and signature 
	public RSACrypt(PrivateKey key){
		try {
			this.rsaPrivKey = key;
			rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsaCipher.init(Cipher.DECRYPT_MODE, rsaPrivKey);
			rsaSig = Signature.getInstance("SHA1withRSA");
			rsaSig.initSign(rsaPrivKey);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
	}
	
	/*
	 * crypt, if RSA object is passed public key, do encrypting
	 * otherwise do decrypting
	 */
	public byte[] crypt(byte[] data){
		int length = 0;
		try {
			if (this.rsaPubKey == null){
				length = (data.length % 128 == 0) ? data.length / 128 : data.length / 128 + 1;
				byte[] plain = new byte[0];
				for (int n = 0; n < length; n ++){
					int start = n * 128;
					int len = Math.min(128, data.length - start);
					plain = Data.mergeBytes(plain, rsaCipher.doFinal(Data.subBytes(data, start, len)));
				}
				return plain;
			}
			else if (this.rsaPrivKey == null){
				length = (data.length % 100 == 0) ? data.length / 100 : data.length / 100 + 1;
				byte[] cipher = new byte[0];
				for (int n = 0; n < length; n ++){
					int start = n * 100;
					int len = Math.min(100, data.length - start);
					cipher = Data.mergeBytes(cipher, rsaCipher.doFinal(Data.subBytes(data, start, len)));
				}
				return cipher;
			}
			return null;
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
			return null;
		} catch (BadPaddingException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	/*
	 * sign a message
	 */
	public byte[] sign(byte[] data){
		try {
			rsaSig.update(data);
			return rsaSig.sign();
		} catch (SignatureException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	/*
	 * verify a signature
	 */
	public boolean verify(byte[] data, byte[] sig){
		try {
			rsaSig.update(data);
			return rsaSig.verify(sig);
		} catch (SignatureException e) {
			e.printStackTrace();
			return false;
		}
	}
}
