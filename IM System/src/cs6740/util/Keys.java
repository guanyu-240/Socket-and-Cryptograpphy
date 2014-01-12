package cs6740.util;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/*
 * Class including AES key generation
 */
public class Keys {
	public static SecretKey genAESKey(int seed){
		try {
			byte[] salt = {1};
			SecretKeyFactory kf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			PBEKeySpec spec= new PBEKeySpec(Integer.toString(seed).toCharArray(), salt, 2048, 256);
			SecretKey tmp = kf.generateSecret(spec);
			SecretKey aesKey = new SecretKeySpec(tmp.getEncoded(), "AES");

			return aesKey;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
			return null;
		}
	}

	/*
	 * generate key from number
	 */
	public static SecretKey genKeyFromNumber(int number){
		return genAESKey(number);
	}
	
	/*
	 * generate key from secret
	 */
	public static SecretKey genKeyFromSecret(byte[] secret){
		byte[] secretNew = Hash.hashMsg(secret, "SHA-256");
		if (secretNew == null){
			return null;
		}
		SecretKey aesKey = new SecretKeySpec(secretNew, "AES");
		return aesKey;
	}
	
	/*
	 * generate IV from secret
	 */
	public static IvParameterSpec genIVFromSecret(byte[] secret){
		byte[] secretNew = Hash.hashMsg(secret, "MD5");
		if (secretNew == null){
			return null;
		}
		IvParameterSpec iv = new IvParameterSpec(secretNew);
		return iv;
	}

}
