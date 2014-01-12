package cs6740.msg.u2uAuth;


import cs6740.msg.Message;
import cs6740.util.AESCrypt;
import cs6740.util.Hash;

public class IdentityRep extends Message{
	/**
	 * 
	 */
	private static final long serialVersionUID = -8452717647179187770L;
	private byte[] cipher;
	private byte[] hmacValue;
	public IdentityRep(AESCrypt aes){
		cipher = aes.encrypt("Verified".getBytes());
		setHmacValue(Hash.hmacMsg(aes.getAESKey().getEncoded(), cipher));
	}
	public byte[] getHmacValue() {
		return hmacValue;
	}
	public void setHmacValue(byte[] hmacValue) {
		this.hmacValue = hmacValue;
	}
	
}
