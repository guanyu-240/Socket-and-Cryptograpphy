package cs6740.auth;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.SocketException;


import cs6740.client.ClientMain;
import cs6740.msg.Message;
import cs6740.msg.u2uAuth.Identity;
import cs6740.msg.u2uAuth.IdentityRep;
import cs6740.msg.u2uAuth.User2UserAuth3;
import cs6740.msg.u2uAuth.User2UserAuth3Ret;
import cs6740.msg.u2uAuth.User2UserAuth4;
import cs6740.msg.u2uAuth.User2UserAuth5;
import cs6740.msg.u2uAuth.User2UserAuth6;
import cs6740.msg.u2uAuth.User2UserAuth5.U2UAuth5Plain;
import cs6740.user.UserInfoWithAES;
import cs6740.user.UserMappingValue;
import cs6740.util.AESCrypt;
import cs6740.util.DHExchange;
import cs6740.util.Data;

/*
 * Class for destination node in user-to-user authentication
 * 
 *  Author: Guanyu Wang, Xiaoyuan Liu
 */
public class User2UserAuthDst {
	private Socket tcpSocket;
	private AESCrypt aesServer;
	private ObjectInputStream objin;
	private ObjectOutputStream objout;
	private String userID;
	private DHExchange dh;
	private int r1;
	private int r2;
	public User2UserAuthDst(Socket tcpSocket, AESCrypt aesServer, String userID){
		this.aesServer = aesServer;
		this.tcpSocket = tcpSocket;
		this.userID = userID;
		this.dh = new DHExchange();
		try {
			tcpSocket.setSoTimeout(1000);
		} catch (SocketException e) {
			return;
		}
	}
	
	// receive message via TCP channel
	private Object receiveMsg(Object obj){
		Object msg;
		try {
			this.objin = new ObjectInputStream(tcpSocket.getInputStream());
			msg = Message.readAnObject(objin);
			if (msg.getClass().equals(obj)){
				return msg;
			}
			System.out.println("Class change detected!");
			return null;
		} catch (ClassNotFoundException e) {
			System.out.println("Class change detected!");
			return null;
		} catch (IOException e) {
			return null;
		}
	}
	
	// send message via TCP channel
	private void sendMsg(Message msg){
		try {
			this.objout = new ObjectOutputStream(tcpSocket.getOutputStream());
			msg.writeMessage(objout);
			objout.flush();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			return;
		}
	}
	
	// process authentication received from source node
	public boolean procAuth(){
		Object obj = null;
		obj = receiveMsg(User2UserAuth3.class);
		//System.out.println("auth3 received");
		User2UserAuth3 auth3 = (User2UserAuth3)obj;
		if (!procAuth3(auth3)){
			return false;
		}
		
		obj = receiveMsg(User2UserAuth5.class);
		User2UserAuth5 auth5 = (User2UserAuth5)obj;
		//System.out.println("auth5 received");
		if (!procAuth5(auth5)){
			return false;
		}
		obj = receiveMsg(Identity.class);
		if (!obj.getClass().equals(Identity.class)){
			return false;
		} 
		Identity id = (Identity)obj;
		UserInfoWithAES user = id.verify(dh.getAes());
		if(user == null){
			return false;
		}

		storeInfo(user);
		IdentityRep reply = new IdentityRep(dh.getAes());
		sendMsg(reply);
		return true;
	}
	
	// store source user information
	private void storeInfo(UserInfoWithAES user){
		byte[] key = Data.mergeBytes(user.getAddr().getAddress(), Data.int2Bytes(user.getUdpPort()));
		UserMappingValue value = new UserMappingValue(user.getUserID(), dh.getAes());
		ClientMain.addToMappings(Data.bytesToLong(key), value);
		ClientMain.addOnlineUser(user.toSuper(), dh.getAes());
		IdentityRep reply = new IdentityRep(dh.getAes());
		sendMsg(reply);
	}
	
	// process User2UserAuth3 
	private boolean procAuth3(User2UserAuth3 auth3){
		User2UserAuth3Ret ret = auth3.verify(aesServer, userID);
		if (ret == null){
			return false;
		}
		byte[] dhPub = dh.genKeyPair();
		dh.genSecKey(ret.getAuth3().getDhPub());
		r1 = ret.getAuth3().getR1();
		r2 = Data.randomNumber(16);
		User2UserAuth4 auth4 = new User2UserAuth4(dhPub, r1, r2, ret.getAesTmp());
		sendMsg(auth4);
		//System.out.println("auth4 sent");
		return true;
	}
	
	// process User2UserAuth5
	private boolean procAuth5(User2UserAuth5 auth5){
		U2UAuth5Plain plain = auth5.verify(dh.getAes(), r2);
		if (plain == null){
			return false;
		}
		User2UserAuth6 auth6 = new User2UserAuth6(dh.getAes(), plain.getR3());
		sendMsg(auth6);
		return true;
	}
}
