package cs6740.msg.u2uAuth;


import java.util.Arrays;

import cs6740.msg.Message;
import cs6740.user.UserInfo;
import cs6740.util.AESCrypt;
import cs6740.util.Data;
import cs6740.util.Hash;

/*
 * Class of 2nd message in user-to-user authentication
 * 
 * Author: Guanyu Wang, Xiaoyuan Liu
 */
public class User2UserAuth2 extends Message {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1126294867820452209L;
	private byte[] cipher;
	private byte[] ticket;
	private byte[] hmacValue;
	
	public User2UserAuth2(AESCrypt aes, byte[] aesKey, byte[]aesIv, UserInfo user, int nonceSrc, byte[] ticket){
		U2UAuth2Plain plain = new U2UAuth2Plain(aesKey, aesIv, user, nonceSrc);
		this.ticket = ticket;
		this.cipher = aes.encrypt(plain.object2Bytes());
		this.hmacValue = Hash.hmacMsg(aes.getAESKey().getEncoded(), Data.mergeBytes(cipher, ticket));
	}
	
	
	public U2UAuth2Plain verify(int nOnce, AESCrypt aes){
		//check hmac
		if (!Arrays.equals(Hash.hmacMsg(aes.getAESKey().getEncoded(), 
				Data.mergeBytes(cipher,  ticket)), hmacValue)){
			System.out.println("HMAC check error");
			return null;
		}
		byte[] plain1Bytes = aes.decrypt(cipher);
		Object msg = Message.bytes2Object(plain1Bytes);
		if (!msg.getClass().equals(U2UAuth2Plain.class)){
			return null;
		}
		U2UAuth2Plain plain2 = (U2UAuth2Plain)msg;
		if (plain2.getNonceSrc() != nOnce){
			return null;
		}
		return plain2;
	}
	
	public byte[] getHmacValue() {
		return hmacValue;
	}
	public void setHmacValue(byte[] hmacValue) {
		this.hmacValue = hmacValue;
	}
	public class U2UAuth2Plain extends Message{
		/**
		 * 
		 */
		private static final long serialVersionUID = -1897084311446989880L;
		private byte[] aesKey;
		private byte[] aesIv;
		private UserInfo user;
		private int nonceSrc;
		public U2UAuth2Plain(byte[] aesKey, byte[] aesIv, UserInfo user, int nonceSrc){
			this.aesKey = aesKey;
			this.aesIv = aesIv;
			this.user = user;
			this.nonceSrc = nonceSrc;
		}
		public UserInfo getUser() {
			return user;
		}
		public void setUser(UserInfo user) {
			this.user = user;
		}
		
		public int getNonceSrc() {
			return nonceSrc;
		}
		public void setNonceSrc(int nonceSrc) {
			this.nonceSrc = nonceSrc;
		}
		public byte[] getAesIv() {
			return aesIv;
		}
		public void setAesIv(byte[] aesIv) {
			this.aesIv = aesIv;
		}
		public byte[] getAesKey() {
			return aesKey;
		}
		public void setAesKey(byte[] aesKey) {
			this.aesKey = aesKey;
		}
	}

	
	public byte[] getTicket() {
		return ticket;
	}
	public void setTicket(byte[] ticket) {
		this.ticket = ticket;
	}
}
