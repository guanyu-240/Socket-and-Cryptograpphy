package cs6740.util;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class DHExchange {
	
	private DHParameterSpec dhParamSpec;
	private KeyPairGenerator keyPairGen;
	private KeyFactory keyFac;
	private KeyAgreement keyAgreement;
	private KeyPair keyPair;
	private AESCrypt aes;
	private boolean readyForAgreement = false;
	
	
	public boolean isReadyForAgreement() {
		return readyForAgreement;
	}
	
	public DHExchange(){
		dhParamSpec = new DHParameterSpec(new BigInteger(1, DH_MODULUS), DH_BASE);
	}
	
	// generate public and private sections for DH Exchange
	public byte[] genKeyPair(){
		try {
			keyPairGen = KeyPairGenerator.getInstance("DH");
			keyPairGen.initialize(dhParamSpec, new SecureRandom());
			keyPair = keyPairGen.generateKeyPair();
			keyAgreement = KeyAgreement.getInstance("DH");
			keyAgreement.init(keyPair.getPrivate());
			readyForAgreement =true;
			return keyPair.getPublic().getEncoded();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
			return null;
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	// Generate key when reaching DH agreement
	public void genSecKey(byte[] pubKeyBytes){
		try {
			keyFac = KeyFactory.getInstance("DH");
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubKeyBytes);
			PublicKey pubKey = keyFac.generatePublic(x509KeySpec);
			keyAgreement.doPhase(pubKey, true);
			byte[] secret = keyAgreement.generateSecret();
			SecretKey key = new SecretKeySpec(Hash.hashMsg(secret, "SHA-256"), "AES");
			IvParameterSpec iv = new IvParameterSpec(Hash.hashMsg(secret, "MD5"));
			this.aes = new AESCrypt(key, iv);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalStateException e) {
			e.printStackTrace();
		}
	}

	public PublicKey getDHPublic(){
		return keyPair.getPublic();
	}
	public AESCrypt getAes() {
		return aes;
	}
	public void setAes(AESCrypt aes) {
		this.aes = aes;
	}
	private static final byte[] DH_MODULUS = {
    	(byte)0xD4, (byte)0xA4, (byte)0x45, (byte)0x4B, 
    	(byte)0x63, (byte)0x99, (byte)0xCB, (byte)0x56, 
    	(byte)0x06, (byte)0x9C, (byte)0x71, (byte)0x7D, 
    	(byte)0x76, (byte)0x3F, (byte)0xFB, (byte)0xAF, 
    	(byte)0x43, (byte)0x38, (byte)0xE4, (byte)0x02, 
    	(byte)0x85, (byte)0x3E, (byte)0xBF, (byte)0x4C, 
    	(byte)0x0D, (byte)0xB7, (byte)0x7C, (byte)0x95, 
    	(byte)0x67, (byte)0x09, (byte)0x2C, (byte)0x04, 
    	(byte)0x39, (byte)0x02, (byte)0x00, (byte)0x4A, 
    	(byte)0x4C, (byte)0x4A, (byte)0x40, (byte)0x09, 
    	(byte)0xD8, (byte)0x37, (byte)0x36, (byte)0x51, 
    	(byte)0x36, (byte)0xC7, (byte)0x26, (byte)0x8C, 
    	(byte)0x92, (byte)0x41, (byte)0xC8, (byte)0xF9, 
    	(byte)0x8E, (byte)0x2C, (byte)0xE3, (byte)0x80, 
    	(byte)0x9D, (byte)0x19, (byte)0x51, (byte)0x90, 
    	(byte)0x14, (byte)0x97, (byte)0xDC, (byte)0x9A, 
    	(byte)0xFD, (byte)0x39, (byte)0x93, (byte)0x1D, 
    	(byte)0x99, (byte)0xD8, (byte)0x06, (byte)0x3B, 
    	(byte)0x42, (byte)0x26, (byte)0xBD, (byte)0x78, 
    	(byte)0x42, (byte)0x9B, (byte)0x33, (byte)0xE9, 
    	(byte)0xEF, (byte)0x0E, (byte)0x00, (byte)0x82, 
    	(byte)0x79, (byte)0x64, (byte)0xBC, (byte)0x30, 
    	(byte)0xDE, (byte)0x94, (byte)0xA4, (byte)0xC6, 
    	(byte)0xBC, (byte)0xA5, (byte)0x70, (byte)0x67, 
    	(byte)0xDF, (byte)0x4F, (byte)0xA2, (byte)0xAC, 
    	(byte)0x3D, (byte)0x7C, (byte)0x9D, (byte)0xD7, 
    	(byte)0xB0, (byte)0x51, (byte)0x7C, (byte)0xF1, 
    	(byte)0xC8, (byte)0xB6, (byte)0x30, (byte)0x7D, 
    	(byte)0x31, (byte)0x0D, (byte)0x9F, (byte)0x8F, 
    	(byte)0x19, (byte)0xD6, (byte)0x6E, (byte)0xED, 
    	(byte)0x02, (byte)0xDC, (byte)0xA4, (byte)0x44, 
    	(byte)0xF5, (byte)0xAD, (byte)0x02, (byte)0x6D
    };
    
    private static final BigInteger DH_BASE = BigInteger.valueOf(5);
}
