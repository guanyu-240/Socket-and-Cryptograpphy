package cs6740.msg.u2uAuth;


import java.util.Arrays;

import cs6740.msg.Message;
import cs6740.util.AESCrypt;
import cs6740.util.Hash;

/*
 * Class of 5th message in user-to-user authentication
 * 
 * Author: Guanyu Wang, Xiaoyuan Liu
 */
public class User2UserAuth5 extends Message {
	/**
	 * 
	 */
	private static final long serialVersionUID = 4012825905418272281L;
	private byte[] cipher;
	private byte[] hmacValue;
	public User2UserAuth5(AESCrypt aes, int r2, int r3){
		U2UAuth5Plain plain5 = new U2UAuth5Plain(r2 + 1, r3);
		cipher = aes.encrypt(plain5.object2Bytes());
		hmacValue = Hash.hmacMsg(aes.getAESKey().getEncoded(), cipher);
	}
	public U2UAuth5Plain verify(AESCrypt aes, int r2){
		//check hmac
		if (!Arrays.equals(hmacValue, Hash.hmacMsg(aes.getAESKey().getEncoded(), cipher))){
			System.out.println("HMAC check error");
			return null;
		}
		Object obj = Message.bytes2Object(aes.decrypt(cipher));
		if (!obj.getClass().equals(U2UAuth5Plain.class)){
			return null;
		}
		U2UAuth5Plain plain = (U2UAuth5Plain)obj;
		if (r2 + 1 != plain.getR2Added()){
			return null;
		}
		return plain;
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
	public class U2UAuth5Plain extends Message{
		/**
		 * 
		 */
		private static final long serialVersionUID = -4463404836268910166L;
		private int r2Added;
		private int r3;
		
		public U2UAuth5Plain(int r2Added, int r3){
			this.r2Added = r2Added;
			this.r3 = r3;
		}
		
		public int getR2Added() {
			return r2Added;
		}
		public void setR2Added(int r2Added) {
			this.r2Added = r2Added;
		}
		public int getR3() {
			return r3;
		}
		public void setR3(int r3) {
			this.r3 = r3;
		}
	}

}
