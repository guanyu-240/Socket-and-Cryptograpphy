package cs6740.util;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/*
 * Class for AES encryption and decryption
 * 
 * Author Guanyu Wang, Xiaoyuan Liu
 */
public class AESCrypt{
	/**
	 * 
	 */
	private SecretKey aesKey;
	private Cipher aesCipher;
	private IvParameterSpec iv;
	public SecretKey getAESKey(){
		return this.aesKey;
	}
	public void setAESKey(SecretKey aesKey){
		this.aesKey = aesKey;
	}
	public IvParameterSpec getIV(){
		return this.iv;
	}
	public AESCrypt(SecretKey aesKey, IvParameterSpec iv){
		try {
			this.aesKey= aesKey; 
			this.iv = iv;
			aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} 
	}
	
	/*
	 * Encrypt message, return cipher 
	 */
	public byte[] encrypt(byte[] data){
		try {
			aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
			return aesCipher.doFinal(data);
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
			return null;
		} catch (BadPaddingException e) {
			e.printStackTrace();
			return null;
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			return null;
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	/*
	 * decrypt message, return plain message
	 */
	public byte[] decrypt(byte[] cipher){
		try {
			aesCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
			return aesCipher.doFinal(cipher);
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
			return null;
		} catch (BadPaddingException e) {
			e.printStackTrace();
			return null;
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			return null;
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
			return null;
		}		
	}
	
	/*
	 * add the key by one
	 */
	public void add1(){
		byte[] newKeyBytes = Data.mergeBytes(aesKey.getEncoded(), Data.int2Bytes(1));
		aesKey = Keys.genKeyFromSecret(newKeyBytes);
	}
}
