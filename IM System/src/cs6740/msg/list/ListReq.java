package cs6740.msg.list;


import java.util.Arrays;

import cs6740.msg.Message;
import cs6740.util.AESCrypt;
import cs6740.util.Data;
import cs6740.util.Hash;
public class ListReq extends Message{

	/**
	 * 
	 */
	private static final long serialVersionUID = -5640671942749511603L;
	private byte[] cipher;
	private byte[] hmacValue;
	public ListReq(AESCrypt aes, String userID, long ts){
		ListReqPlain plain = new ListReqPlain(userID, ts);
		cipher = aes.encrypt(plain.object2Bytes());
		hmacValue = Hash.hmacMsg(aes.getAESKey().getEncoded(), cipher);
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

	public ListReqPlain verify(AESCrypt aes, String userID){
		if (!Arrays.equals(hmacValue, Hash.hmacMsg(aes.getAESKey().getEncoded(), cipher))){
			System.out.println("HMAC check error");
			return null;
		}
		Object obj = Message.bytes2Object(aes.decrypt(cipher)); 
		if (obj.getClass().equals(ListReqPlain.class)){
			ListReqPlain plain = (ListReqPlain)obj;
			long ts = Data.timestamp();
			if (userID.equals(plain.getUserID()) && Math.abs(ts - plain.getTs()) < 10000){
				return plain;
			}
			return null;
		}
		return null;
	}
	public class ListReqPlain extends Message{

		/**
		 * 
		 */
		private static final long serialVersionUID = 2249216197321295439L;
		private String userID;
		private long ts;
		public ListReqPlain(String userID, long ts){
			this.userID = userID;
			this.ts = ts;
		}
		public String getUserID() {
			return userID;
		}
		public void setUserID(String userID) {
			this.userID = userID;
		}

		public long getTs() {
			return ts;
		}
		public void setTs(long ts) {
			this.ts = ts;
		}
	}
}
