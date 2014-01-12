package cs6740.msg.u2uAuth;

import cs6740.msg.Message;
import cs6740.util.AESCrypt;
import cs6740.util.Hash;

/*
 * Class of 1st message in user-to-user authentication
 * 
 * Author: Guanyu Wang, Xiaoyuan Liu
 */
public class User2UserAuth1 extends Message {
	/**
	 * 
	 */
	private static final long serialVersionUID = 5250924113285160992L;
	private byte[] cipher;
	private byte[] hmacValue;
	public User2UserAuth1(String srcUsrID, String tgtUserID, int nOnce, AESCrypt aes){
		U2UAuth1Plain plain = new U2UAuth1Plain(srcUsrID, tgtUserID, nOnce);
		this.cipher = aes.encrypt(plain.object2Bytes());
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
	
	
	public class U2UAuth1Plain extends Message{
		/**
		 * 
		 */
		private static final long serialVersionUID = -6874761559516137652L;
		private String srcUserId;
		private String tgtUserId;
		private int nonceSrc;
		public U2UAuth1Plain(String srcUserID, String tgtUserID, int nOnce){
			this.srcUserId = srcUserID;
			this.tgtUserId = tgtUserID;
			this.nonceSrc = nOnce;
		}
		public String getSrcUserId() {
			return srcUserId;
		}
		public void setSrcUserId(String srcUserId) {
			this.srcUserId = srcUserId;
		}
		public String getTgtUserId() {
			return tgtUserId;
		}
		public void setTgtUserId(String tgtUserId) {
			this.tgtUserId = tgtUserId;
		}
		public int getNonceSrc() {
			return nonceSrc;
		}
		public void setNonceSrc(int nonceSrc) {
			this.nonceSrc = nonceSrc;
		}
	}

}
