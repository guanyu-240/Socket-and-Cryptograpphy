package cs6740.msg.logout;


import java.util.Arrays;

import cs6740.msg.Message;
import cs6740.server.ServerThread;
import cs6740.util.AESCrypt;
import cs6740.util.Data;
import cs6740.util.Hash;

/**
 * Class of 1st message in logout process
 * 
 * @author Guanyu Wang, Xiaoyuan Liu
 *
 */
public class LogoutReq extends Message{

	/**
	 * 
	 */
	private static final long serialVersionUID = 4606318854352105962L;
	private byte[] cipher;
	private byte[] hmacValue;
	
	public LogoutReq(AESCrypt aes, long ts){
		cipher = aes.encrypt(Data.long2Bytes(ts));
		setHmacValue(Hash.hmacMsg(aes.getAESKey().getEncoded(), cipher));
	}
	

	public long verify(AESCrypt aes){
		if (!Arrays.equals(hmacValue, Hash.hmacMsg(aes.getAESKey().getEncoded(), cipher))){
			System.out.println("HMAC check error");
			return -1;
		}
		long tsNew = Data.timestamp();
		long ts = Data.bytesToLong(aes.decrypt(cipher));
		if (tsNew - ts > 0 && tsNew - ts < ServerThread.RATIONAL_TS_DIFF){
			return ts + 1;
		}
		return -1;
	}


	public byte[] getHmacValue() {
		return hmacValue;
	}


	public void setHmacValue(byte[] hmacValue) {
		this.hmacValue = hmacValue;
	}
	
}
