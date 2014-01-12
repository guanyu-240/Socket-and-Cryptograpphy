package cs6740.user;

import java.net.InetAddress;


import cs6740.msg.Message;
import cs6740.util.AESCrypt;

public class UserInfo extends Message{
	/**
	 * 
	 */
	private static final long serialVersionUID = -3326495968917715304L;
	protected String userID;
	protected InetAddress addr;
	protected int udpPort;
	protected int listeningPort;
	public String getUserID() {
		return userID;
	}
	public void setUserID(String userID) {
		this.userID = userID;
	}
	public InetAddress getAddr() {
		return addr;
	}
	public void setAddr(InetAddress addr) {
		this.addr = addr;
	}
	public UserInfo(String userID, InetAddress addr, int udpPort, int listeningPort){
		this.userID = userID;
		this.addr = addr;
		this.udpPort = udpPort;
		this.listeningPort = listeningPort;
	}
	
	public UserInfoWithAES toChild(AESCrypt aes){
		UserInfoWithAES sUser = new UserInfoWithAES(userID, addr, udpPort, listeningPort, aes);
		return sUser;
	}
	public int getUdpPort() {
		return udpPort;
	}
	public void setUdpPort(int udpPort) {
		this.udpPort = udpPort;
	}
	public int getListeningPort() {
		return listeningPort;
	}
	public void setListeningPort(int listeningPort) {
		this.listeningPort = listeningPort;
	}
}
