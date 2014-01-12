package cs6740.msg.u2uAuth;



import java.util.Arrays;

import cs6740.msg.Message;
import cs6740.util.AESCrypt;
import cs6740.util.Hash;

/*
 * Class of 4th message in user-to-user authentication
 * 
 * Author: Guanyu Wang, Xiaoyuan Liu
 */
public class User2UserAuth4 extends Message {
	/**
	 * 
	 */
	private static final long serialVersionUID = 6767665451618085588L;
	private byte[] cipher;
	private byte[] hmacValue;

	public User2UserAuth4(byte[] dhPub, int r1, int r2, AESCrypt aesTmp){
		U2UAuth4Plain plain = new U2UAuth4Plain(dhPub, r1 + 1, r2);
		AESCrypt aesTmpNew = aesTmp;
		aesTmpNew.add1();
		this.cipher = aesTmpNew.encrypt(plain.object2Bytes());
		this.hmacValue = Hash.hmacMsg(aesTmp.getAESKey().getEncoded(), cipher);
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
	
	/*
	 * verification of the message
	 */
	public User2UserAuth4Ret verify(AESCrypt aes, int r1){
		// hmac check
		aes.add1();
		if (!Arrays.equals(hmacValue, Hash.hmacMsg(aes.getAESKey().getEncoded(), cipher))){
			System.out.println("HMAC check error");
			return null;
		}
		
		Object msg = Message.bytes2Object(aes.decrypt(cipher));
		if (msg == null || !msg.getClass().equals(U2UAuth4Plain.class)){
			return null;
		}
		U2UAuth4Plain plain4 = (U2UAuth4Plain)msg;
		if (plain4.getR1Added() != (r1 + 1)){
			return null;
		}
		return (new User2UserAuth4Ret(plain4.r2, plain4.dhPub));
	}
	
	class U2UAuth4Plain extends Message{
		/**
		 * 
		 */
		private static final long serialVersionUID = -4763606042541404057L;

		private byte[] dhPub;
		private int r1Added;
		private int r2;
		
		public U2UAuth4Plain(byte[] dhPub, int r1Added, int r2){
			this.dhPub = dhPub;
			this.r1Added = r1Added;
			this.r2 = r2;
		}
		
		public byte[] getDhPub() {
			return dhPub;
		}
		public void setDhPub(byte[] dhPub) {
			this.dhPub = dhPub;
		}

		public int getR1Added() {
			return r1Added;
		}

		public void setR1Added(int r1Added) {
			this.r1Added = r1Added;
		}

		public int getR2() {
			return r2;
		}
		public void setR2(int r2) {
			this.r2 = r2;
		}
	}
}
