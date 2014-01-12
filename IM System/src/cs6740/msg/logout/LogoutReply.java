package cs6740.msg.logout;

import java.util.Arrays;

import cs6740.msg.Message;
import cs6740.util.AESCrypt;
import cs6740.util.Data;
import cs6740.util.Hash;

/**
 * Class of 2nd message in logout process
 * 
 * @author Guanyu Wang, Xiaoyuan Liu
 *
 */
public class LogoutReply extends Message{

	/**
	 * 
	 */
	private static final long serialVersionUID = 4606318854352105962L;
	
	private byte[] cipher;
	private byte[] hmacValue;
	public byte[] getHmacValue() {
		return hmacValue;
	}

	public void setHmacValue(byte[] hmacValue) {
		this.hmacValue = hmacValue;
	}

	public LogoutReply(AESCrypt aes, long tsAdded){
		this.cipher = aes.encrypt(Data.long2Bytes(tsAdded));
		this.setHmacValue(Hash.hmacMsg(aes.getAESKey().getEncoded(), cipher));
	}
	
	public boolean verify(AESCrypt aes, long ts){
		if (!Arrays.equals(hmacValue, Hash.hmacMsg(aes.getAESKey().getEncoded(), cipher))){
			System.out.println("HMAC check error");
			return false;
		}
		long tsAdded = Data.bytesToLong(aes.decrypt(cipher));
		if (tsAdded - ts == 1){
			return true;
		}
		return false;
	}
}
