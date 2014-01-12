package cs6740.msg.u2uAuth;

import java.util.Arrays;


import cs6740.msg.Message;
import cs6740.user.UserInfo;
import cs6740.user.UserInfoWithAES;
import cs6740.util.AESCrypt;
import cs6740.util.Hash;

public class Identity extends Message{
	/**
	 * 
	 */
	private static final long serialVersionUID = -8452717647179187770L;
	private byte[] cipher;
	private byte[] hmacValue;
	public Identity(UserInfo user, AESCrypt aes){
		cipher = aes.encrypt(user.object2Bytes());
		hmacValue = Hash.hmacMsg(aes.getAESKey().getEncoded(), cipher);
	}
	
	public UserInfoWithAES verify(AESCrypt aes){
		//check hmac
		if (Arrays.equals(Hash.hmacMsg(aes.getAESKey().getEncoded(), cipher), hmacValue)){
			Object obj  = Message.bytes2Object(aes.decrypt(cipher));
			if (obj.getClass().equals(UserInfo.class)){
				UserInfo user = (UserInfo)obj;
				return user.toChild(aes);
			}
			return null;
		}
		System.out.println("HMAC check error");
		return null;
	}
	
}
