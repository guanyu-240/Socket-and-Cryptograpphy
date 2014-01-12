package cs6740.util;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Hash {
	public static final String HMAC_ALGO = "HmacSHA1";
	public static byte[] hash(byte[] data, String method) throws NoSuchAlgorithmException{
		MessageDigest md = MessageDigest.getInstance(method);
		return md.digest(data);
	}
	
	// function to hash general data
	public static byte[] hashMsg(byte[] data, String method){
		byte[] ret = data;
		try{
			ret = hash(ret, method);
		}catch(NoSuchAlgorithmException ex){
			ex.printStackTrace();
			return null;
		}
		return ret;
	}
	
	// function to hash password and salt
	public static byte[] hashPasswd(String passwd, String salt, String method){
		StringBuilder sb = new StringBuilder(passwd);
		sb.append(salt);
		byte[] ret = sb.toString().getBytes();
		try{
			for (int n = 0; n < 128; n ++){
				ret = hash(ret, method);
			}
		}catch(NoSuchAlgorithmException ex){
			ex.printStackTrace();
			return null;
		}
		return ret;
	}
	
	public static byte[] hashPasswd(String pwd, String salt){
		try {
			SecretKeyFactory kf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			PBEKeySpec spec= new PBEKeySpec(pwd.toCharArray(), salt.getBytes(), 128, 256);
			SecretKey tmp = kf.generateSecret(spec);
			return tmp.getEncoded();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	// function to get the HMAC of data
	public static byte[] hmacMsg(byte[] keyBytes, byte[] data){
		try {
			Mac hmac = Mac.getInstance(HMAC_ALGO);
			SecretKey key = new SecretKeySpec(keyBytes, hmac.getAlgorithm());
			hmac.init(key);
			hmac.update(data);
			return hmac.doFinal();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public boolean verifyHmac(byte[] hashValue, byte[] keyBytes, byte[] data){
		return Arrays.equals(hashValue, hmacMsg(keyBytes, data));
	}
}
