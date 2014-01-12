package cs6740.user;

import java.net.InetAddress;

import cs6740.util.AESCrypt;

public class UserInfoWithAES extends UserInfo{
	/**
	 * 
	 */
	private static final long serialVersionUID = -3326495968917715304L;
	private AESCrypt aes;

	public UserInfoWithAES(String userID, InetAddress addr, int udpPort, int listeningPort, AESCrypt aes){
		super(userID, addr, udpPort, listeningPort);
		this.setAes(aes);
	}

	public UserInfo toSuper(){
		UserInfo user = new UserInfo(userID, addr, udpPort, listeningPort);
		return user;
	}
	public AESCrypt getAes() {
		return aes;
	}

	public void setAes(AESCrypt aes) {
		this.aes = aes;
	}

}
