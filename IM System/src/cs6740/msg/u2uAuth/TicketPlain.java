package cs6740.msg.u2uAuth;

import cs6740.msg.Message;

public class TicketPlain extends Message{
	/**
	 * 
	 */
	private static final long serialVersionUID = -6709630038596097256L;
	private byte[] aesKey;
	private byte[] aesIV;
	private String dstUserId;

	public TicketPlain(byte[] aesKey, byte[] aesIV, String dstUserID){
		this.setAesKey(aesKey);
		this.setAesIV(aesIV);
		this.dstUserId = dstUserID;
	}
	
	public byte[] getAesKey() {
		return aesKey;
	}

	public void setAesKey(byte[] aesKey) {
		this.aesKey = aesKey;
	}

	public byte[] getAesIV() {
		return aesIV;
	}

	public void setAesIV(byte[] aesIV) {
		this.aesIV = aesIV;
	}

	public String getDstUserId() {
		return dstUserId;
	}

	public void setDstUserId(String dstUserId) {
		this.dstUserId = dstUserId;
	}

}
