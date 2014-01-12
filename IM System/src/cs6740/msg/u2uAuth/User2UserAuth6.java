package cs6740.msg.u2uAuth;


import java.util.Arrays;

import cs6740.msg.Message;
import cs6740.util.AESCrypt;
import cs6740.util.Data;
import cs6740.util.Hash;

/*
 * Class of 6th message in user-to-user authentication
 * 
 * Author: Guanyu Wang, Xiaoyuan Liu
 */
public class User2UserAuth6 extends Message {
	/**
	 * 
	 */
	private static final long serialVersionUID = -3997156734692729858L;
	private byte[] cipher;
	private byte[] hmacValue;
	public User2UserAuth6(AESCrypt aes, int r3){
		cipher = aes.encrypt(Data.int2Bytes(r3 + 1));
		hmacValue = Hash.hmacMsg(aes.getAESKey().getEncoded(), cipher);
	}
	public boolean verify(AESCrypt aes, int r3){
		//check hmac
		if (!Arrays.equals(hmacValue, Hash.hmacMsg(aes.getAESKey().getEncoded(), cipher))){
			System.out.println("HMAC check error");
			return false;
		}
		int r3Added = Data.bytesToInt(aes.decrypt(cipher));
		if (r3Added == r3 + 1){
			return true;
		}
		return false;
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
