package cs6740.msg.u2uAuth;

import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;


import cs6740.msg.Message;
import cs6740.util.AESCrypt;
import cs6740.util.Data;
import cs6740.util.Hash;
import cs6740.util.Keys;

/*
 * Class of 3rd message in user-to-user authentication
 * 
 * Author: Guanyu Wang, Xiaoyuan Liu
 */
public class User2UserAuth3 extends Message {

	/**
	 * 
	 */
	private static final long serialVersionUID = 2375634771739613651L;
	private byte[] ticket;
	private byte[] cipher;
	private byte[] hmacValue;

	public User2UserAuth3(byte[] dhPub, int r1, AESCrypt aes, byte[] ticket){
		U2UAuth3Plain auth3 = new U2UAuth3Plain(dhPub, r1);
		cipher = aes.encrypt(auth3.object2Bytes());
		this.setTicket(ticket);
		this.hmacValue = Hash.hmacMsg(aes.getAESKey().getEncoded(), Data.mergeBytes(ticket, cipher));
	}
	
	/*
	 * verification of the message
	 */
	public User2UserAuth3Ret verify(AESCrypt aesServer, String userID){
		byte[] ticketPlainBytes = aesServer.decrypt(ticket);
		Object obj = Message.bytes2Object(ticketPlainBytes);
		if (!obj.getClass().equals(TicketPlain.class)){
			return null;
		}
		TicketPlain tPlain = (TicketPlain)obj;
		if (!tPlain.getDstUserId().equals(userID)){
			return null;
		}
		SecretKey tmpKey = Keys.genKeyFromSecret(tPlain.getAesKey());
		IvParameterSpec tmpIv = Keys.genIVFromSecret(tPlain.getAesIV());
		AESCrypt aesTmp = new AESCrypt(tmpKey, tmpIv);
		obj = Message.bytes2Object(aesTmp.decrypt(cipher));
		// hmac check
		if (!Arrays.equals(hmacValue, 
				Hash.hmacMsg(aesTmp.getAESKey().getEncoded(), Data.mergeBytes(ticket, cipher)))){
			System.out.println("HMAC check error");
			return null;
		}
		if (!obj.getClass().equals(U2UAuth3Plain.class)){
			return null;
		}
		U2UAuth3Plain plain = (U2UAuth3Plain)obj;
		return new User2UserAuth3Ret(plain, aesTmp);
	}
	
	public byte[] getTicket() {
		return ticket;
	}

	public void setTicket(byte[] ticket) {
		this.ticket = ticket;
	}

	public byte[] getHmacValue() {
		return hmacValue;
	}
	public void setHmacValue(byte[] hmacValue) {
		this.hmacValue = hmacValue;
	}

	public class U2UAuth3Plain extends Message{

		/**
		 * 
		 */
		private static final long serialVersionUID = 3086633116438199891L;
		private byte[] dhPub;
		private int r1;
		public U2UAuth3Plain(byte[] dhPub, int r1){
			this.setDhPub(dhPub);
			this.r1 = r1;
		}

		public byte[] getDhPub() {
			return dhPub;
		}
		public void setDhPub(byte[] dhPub) {
			this.dhPub = dhPub;
		}

		public int getR1() {
			return r1;
		}
		public void setR1(int r1) {
			this.r1 = r1;
		}
	}
}
