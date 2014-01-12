package cs6740.msg.loginAuth;
import java.util.Arrays;


import cs6740.msg.Message;
import cs6740.util.AESCrypt;
import cs6740.util.Data;
import cs6740.util.Hash;

/*
 * Class of 5th message in login authentication
 * 
 * Author: Guanyu Wang, Xiaoyuan Liu
 */
public class LoginAuth5 extends Message {
	/**
	 * 
	 */
	private static final long serialVersionUID = 7097804944670389071L;
	private byte[] cipher;
	private byte[] hmacValue;
	
	public LoginAuth5(){}
	public LoginAuth5(int r3, AESCrypt aes){
		this.cipher = aes.encrypt(Data.int2Bytes(r3 + 1));
		this.hmacValue = Hash.hmacMsg(aes.getAESKey().getEncoded(), cipher);
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
	
	public boolean verify(int r3, AESCrypt aes){
		// hmac check
		if (!Arrays.equals(hmacValue, Hash.hmacMsg(aes.getAESKey().getEncoded(), cipher))){
			System.out.println("HMAC check error");
			return false;
		}
		int r3Added = Data.bytesToInt(aes.decrypt(cipher));
		if (r3 + 1 != r3Added){
			System.out.println("R3 check error");
			return false;
		}
		return true;
	}

}
