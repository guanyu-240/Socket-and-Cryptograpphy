package cs6740.auth;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
//import java.net.SocketException;


import cs6740.client.ClientMain;
import cs6740.msg.Message;
import cs6740.msg.u2uAuth.Identity;
import cs6740.msg.u2uAuth.IdentityRep;
import cs6740.msg.u2uAuth.User2UserAuth1;
import cs6740.msg.u2uAuth.User2UserAuth2;
import cs6740.msg.u2uAuth.User2UserAuth3;
import cs6740.msg.u2uAuth.User2UserAuth4;
import cs6740.msg.u2uAuth.User2UserAuth4Ret;
import cs6740.msg.u2uAuth.User2UserAuth5;
import cs6740.msg.u2uAuth.User2UserAuth6;
import cs6740.msg.u2uAuth.User2UserAuth2.U2UAuth2Plain;
import cs6740.user.UserInfo;
import cs6740.user.UserMappingValue;
import cs6740.util.AESCrypt;
import cs6740.util.DHExchange;
import cs6740.util.Data;
import cs6740.util.Keys;

/*
 * Class used for source node of user-to-user authentication
 * 
 * Author: Guanyu Wang, Xiaoyuan Liu
 */
public class User2UserAuthSrc {
	private AESCrypt aesServer;
	private AESCrypt aesTmp;
	private AESCrypt aes;
	private UserInfo dstUser;
	private int nOnce;
	private Socket tcpSocket2Server;
	private Socket tcpSocket2Client;
	private InetAddress tgtAddr;
	private int tgtPort;
	private DHExchange dh;
	private ObjectInputStream objin;
	private ObjectOutputStream objout;
	private int r1;
	private int r3;
	public Socket gettcpSocket2Server() {
		return tcpSocket2Server;
	}

	public void settcpSocket2Server(Socket tcpSocket2Server) {
		this.tcpSocket2Server = tcpSocket2Server;
	}

	public User2UserAuthSrc(Socket tcpSocket2Server, AESCrypt aes){
		try {
			tcpSocket2Server.setSoTimeout(1500);
		} catch (SocketException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		nOnce = Data.randomNumber(16);
		this.tcpSocket2Server = tcpSocket2Server;
		this.aesServer = aes;
	}
	
	/*
	 *  receive message via tcp channel
	 */
	private Object receiveMsgTCP(Object obj, Socket sock){
		Object msg;
		try {
			this.objin = new ObjectInputStream(sock.getInputStream());
			msg = Message.readAnObject(objin);
			//System.out.println(msg.getClass().getName());
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

	
	
	/*
	 *  send message via tcp channel
	 */
	private void sendMsg(Message msg, Socket sock){
		try {
			this.objout = new ObjectOutputStream(sock.getOutputStream());
			msg.writeMessage(objout);
			objout.flush();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			return;
		}
	}

	/*
	 *  start a user to user request
	 */
	public boolean commandRequest(String srcUserID, String tgtUserID, int udpPort, int tcpPort){
		Object msg = null;
		User2UserAuth1 auth1 = new User2UserAuth1(srcUserID, tgtUserID, nOnce, aesServer);
		sendMsg(auth1, tcpSocket2Server);
		msg =receiveMsgTCP(User2UserAuth2.class, tcpSocket2Server);
		if (msg == null){
			return false;
		}
		
		User2UserAuth3 auth3 = procU2UAuth2((User2UserAuth2)msg);
		if (auth3 == null){
			return false;
		}
		
		sendMsg(auth3, tcpSocket2Client);
		msg = receiveMsgTCP(User2UserAuth4.class, tcpSocket2Client);
		if (msg == null){
			return false;
		}
		User2UserAuth5 auth5 = procU2UAuth4((User2UserAuth4)msg);
		if (auth5 == null){
			return false;
		}
		sendMsg(auth5, tcpSocket2Client);
		msg = receiveMsgTCP(User2UserAuth6.class, tcpSocket2Client);
		if (msg == null){
			return false;
		}
		Identity id = procU2UAuth6((User2UserAuth6)msg, srcUserID, udpPort, tcpPort);
		sendMsg(id, tcpSocket2Client);
		receiveMsgTCP(IdentityRep.class, tcpSocket2Client);
		storeInfo();
		return true;
	}
	
	/*
	 *  store the information of destination user
	 */
	private void storeInfo(){
		byte[] key = Data.mergeBytes(dstUser.getAddr().getAddress(), Data.int2Bytes(dstUser.getUdpPort()));
		UserMappingValue value = new UserMappingValue(dstUser.getUserID(), aes);
		ClientMain.addToMappings(Data.bytesToLong(key), value);
		ClientMain.addOnlineUser(dstUser, aes);
	}
	
	/*
	 *  process User2UserAuth2 message received from server
	 */
	private User2UserAuth3 procU2UAuth2(User2UserAuth2 auth2){
		U2UAuth2Plain plain2 = auth2.verify(nOnce, aesServer);
		if (plain2 == null){
			return null;
		}
		//System.out.println("Verify success");
		this.dstUser = plain2.getUser();
		this.tgtAddr = plain2.getUser().getAddr();
		this.tgtPort = plain2.getUser().getListeningPort();
		try {
			//System.out.println("trying to connect " + tgtAddr.getHostAddress() + ":" + tgtPort);
			this.tcpSocket2Client = new Socket(tgtAddr, tgtPort);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			return null;
		}
		SecretKey key = Keys.genKeyFromSecret(plain2.getAesKey());
		IvParameterSpec iv = Keys.genIVFromSecret(plain2.getAesIv());
		this.aesTmp = new AESCrypt(key, iv);
		this.r1 = Data.randomNumber(16);
		dh = new DHExchange();
		byte[] dhPub= dh.genKeyPair();
		User2UserAuth3 auth3 = new User2UserAuth3(dhPub, r1, aesTmp, auth2.getTicket());
		return auth3;
	}
	
	/*
	 *  process User2UserAuth4 message received from destination client
	 */
	private User2UserAuth5 procU2UAuth4(User2UserAuth4 auth4){
		User2UserAuth4Ret verifyRet = auth4.verify(aesTmp, r1);
		if (verifyRet == null){
			return null;
		}
		byte[] dhPub = verifyRet.getDhPub();
		int r2 = verifyRet.getR2();
		dh.genSecKey(dhPub);
		r3 = Data.randomNumber(16);
		User2UserAuth5 auth5 = new User2UserAuth5(dh.getAes(), r2, r3);
		return auth5;
	}
	
	/*
	 *  process User2UserAuth6 message received from destination client
	 */
	private Identity procU2UAuth6(User2UserAuth6 auth6, String srcUserID, int udpPort, int tcpPort){
		aes = dh.getAes();
		if (!auth6.verify(aes, r3)){
			return null;
		}
		UserInfo user = new UserInfo(srcUserID, tcpSocket2Client.getLocalAddress(), udpPort, tcpPort);
		Identity id = new Identity(user, aes);
		return id;
	}
}
