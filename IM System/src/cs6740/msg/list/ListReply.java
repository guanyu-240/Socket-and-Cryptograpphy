package cs6740.msg.list;


import java.util.Arrays;

import cs6740.msg.Message;
import cs6740.util.AESCrypt;
import cs6740.util.Hash;

public class ListReply extends Message {

	/**
	 * 
	 */
	private static final long serialVersionUID = -7138180052874120055L;
	private byte[] cipher;
	private byte[] hmacValue;
	public ListReply(AESCrypt aes, String[] usersList, long ts){
		ListReplyPlain lreply = new ListReplyPlain(usersList, ts);
		cipher = aes.encrypt(lreply.object2Bytes());
		hmacValue = Hash.hmacMsg(aes.getAESKey().getEncoded(), cipher);
	}
	
	public String[] verify(AESCrypt aes, long ts){
		if (!Arrays.equals(hmacValue, Hash.hmacMsg(aes.getAESKey().getEncoded(), cipher))){
			System.out.println("HMAC check error");
			return null;
		}
		Object msg = Message.bytes2Object(aes.decrypt(cipher));
		if (msg.getClass().equals(ListReplyPlain.class)){
			ListReplyPlain plain = (ListReplyPlain)msg;
			
			if (plain.getTs() - ts == 1){
				return plain.getUsersList();
			}
			return null;
		}
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

	public class ListReplyPlain extends Message{

		/**
		 * 
		 */
		private static final long serialVersionUID = -5169517732218441494L;
		private String[] usersList;
		private long ts;
		public ListReplyPlain(String[] usersList, long ts){
			this.usersList = usersList;
			this.ts = ts;
		}
		public String[] getUsersList() {
			return usersList;
		}
		public void setUsersList(String[] usersList) {
			this.usersList = usersList;
		}
		public long getTs() {
			return ts;
		}
		public void setTs(long ts) {
			this.ts = ts;
		}
	}
}
