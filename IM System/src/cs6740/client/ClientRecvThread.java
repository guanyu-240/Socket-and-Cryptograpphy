package cs6740.client;

import java.io.Console;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;


import cs6740.msg.Message;
import cs6740.msg.imsg.InstantMessage;
import cs6740.user.UserInfoWithAES;
import cs6740.user.UserMappingValue;
import cs6740.util.AESCrypt;
import cs6740.util.Data;

/*
 * Thread which client use for receiving UDP packet
 */
public class ClientRecvThread extends Thread{

	/**
	 * @param args
	 */
	private DatagramSocket udpSocket;
	private DatagramPacket dPacket;
	private InetAddress serverAddr;
	private int serverPort;
	private AESCrypt aesServer;

	public ClientRecvThread(DatagramSocket udpSocket, Console cons, 
			InetAddress serverAddr, int serverPort, AESCrypt aesServer){
		this.udpSocket = udpSocket;
		this.serverAddr = serverAddr;
		this.serverPort = serverPort;
		this.aesServer = aesServer;
	}
	
	/*
	 *  process instant message
	 */
	public void procIMMessage(){
		byte[] data = dPacket.getData();
		Object obj = Message.bytes2Object(data);
		if (!obj.getClass().equals(InstantMessage.class)){
			return;
		}
		InstantMessage msg = (InstantMessage)obj;
		if (isFromServer()){
			String userID = msg.verify(aesServer);
			logoutUser(userID);
			return;
		}
		byte[] mKey = Data.mergeBytes(dPacket.getAddress().getAddress(), Data.int2Bytes(dPacket.getPort()));
		UserMappingValue mValue = ClientMain.searchUserByInetInfo(Data.bytesToLong(mKey));
		if (mValue == null){
			return;
		}
		String msgPlain = msg.verify(mValue.getAes());
		if (msgPlain == null){
			return;
		}
	
		System.out.printf("From %s: %s\n", mValue.getUserID(), msgPlain);
	}
	
	/*
	 * remove logout user from local table
	 */
	private void logoutUser(String userID){
		System.out.println("Logout " + userID);
		UserInfoWithAES user = ClientMain.searchUser(userID);
		if (user == null){
			return;
		}
		ClientMain.removeOnlineUser(userID);
		long addrAndPort = Data.bytesToLong(Data.mergeBytes(user.getAddr().getAddress(), Data.int2Bytes(user.getUdpPort())));
		ClientMain.removeMapping(addrAndPort);
	}
	
	/*
	 * check if packet comes from the server, if yes, it's a packet which server uses
	 * to notify users of removing the offline user
	 */
	private boolean isFromServer(){
		return dPacket.getAddress().equals(serverAddr) && dPacket.getPort() == serverPort;
	}
	
	public void run(){
		while(true){
			try {
				byte[] data = new byte[Message.MAXLEN];
				dPacket = new DatagramPacket(data, data.length);
				udpSocket.receive(dPacket);
				System.out.println("Received msg");
				procIMMessage();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				continue;
			}
		}
	}
}
