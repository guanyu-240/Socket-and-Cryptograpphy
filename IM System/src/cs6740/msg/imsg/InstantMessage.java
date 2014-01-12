package cs6740.msg.imsg;

import java.util.Arrays;


import cs6740.msg.Message;
import cs6740.util.AESCrypt;
import cs6740.util.Hash;

public class InstantMessage extends Message {

	/**
	 * 
	 */
	private static final long serialVersionUID = 5726064478850910558L;
	private byte[] cipher;
	private byte[] hmacValue;
	
	public InstantMessage(String plain, AESCrypt aes){
		cipher = aes.encrypt(plain.getBytes());
		hmacValue = Hash.hmacMsg(aes.getAESKey().getEncoded(), cipher);
	}
	
	public String verify(AESCrypt aes){
		if (Arrays.equals(hmacValue, Hash.hmacMsg(aes.getAESKey().getEncoded(), cipher))){
			byte[] plain = aes.decrypt(cipher);
			return new String(plain);
		}
		System.out.println("Integrity destruction detected!");
		return null;
	}
	
	public byte[] getCipher() {
		return cipher;
	}
	public void setCipher(byte[] cipher) {
		this.cipher = cipher;
	}
	public byte[] getHmacValue() {
		return hmacValue;
	}
	public void setHmacValue(byte[] hmacValue) {
		this.hmacValue = hmacValue;
	}
	
}
