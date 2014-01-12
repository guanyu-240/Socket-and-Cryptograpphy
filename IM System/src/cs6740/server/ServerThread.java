package cs6740.server;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.net.SocketException;


import cs6740.auth.LoginAuthServer;
import cs6740.msg.Message;
import cs6740.msg.list.ListReply;
import cs6740.msg.list.ListReq;
import cs6740.msg.list.ListReq.ListReqPlain;
import cs6740.msg.logout.LogoutReply;
import cs6740.msg.logout.LogoutReq;
import cs6740.msg.u2uAuth.TicketPlain;
import cs6740.msg.u2uAuth.User2UserAuth1;
import cs6740.msg.u2uAuth.User2UserAuth2;
import cs6740.msg.u2uAuth.User2UserAuth1.U2UAuth1Plain;
import cs6740.user.UserInfo;
import cs6740.util.AESCrypt;
import cs6740.util.Data;

/*
 * Server thread, created when server accepts TCP connection
 * 
 * Author: Guanyu Wang, Xiaoyuan Liu
 */
public class ServerThread extends Thread{

	/**
	 * @param args
	 */
	public static long RATIONAL_TS_DIFF = 10000; 
	
	private LoginAuthServer loginAuth;
	private Socket tcpSocket;
	private AESCrypt aes;
	private UserInfo user;
	private Object msg;
	private ObjectInputStream objin;
	private ObjectOutputStream objout;
	
	public ServerThread(Socket tcpSocket){
		this.tcpSocket = tcpSocket;
		
	}
	
	private void storeInfo(){
		this.aes = loginAuth.getAes();
		this.user = loginAuth.getUser();
		ServerMain.addOnlineUser(user, aes);
	}

	
	public void run(){
		loginAuth = new LoginAuthServer(tcpSocket);
		boolean retLogin = loginAuth.procLoginAuth();
		if (!retLogin){
			if (!tcpSocket.isClosed()){
				try {
					tcpSocket.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
				return;
			}
			return;
		}
		try {
			tcpSocket.setSoTimeout(0);
		} catch (SocketException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		storeInfo();
		System.out.println("User info stored");
		receiveMsg();
	}
	
	private void receiveMsg(){
		while(true){
			try {
				this.objin = new ObjectInputStream(tcpSocket.getInputStream());
				msg = Message.readAnObject(objin);
				if (msg == null){
					continue;
				}
				if (msg.getClass().equals(ListReq.class)){
					procListReq();
				}
				else if (msg.getClass().equals(User2UserAuth1.class)){
					procU2UAuth();
				}
				else if (msg.getClass().equals(LogoutReq.class)){
					procLogout();
				}
			} catch (ClassNotFoundException e) {
				System.out.println("Class change detected!");
				// TODO Auto-generated catch block
				
			} catch (IOException e) {
				//System.out.println(e.getMessage());
				//e.printStackTrace();
				ServerMain.removeOnlineUser(user.getUserID());
				ServerMain.multicast(user.getUserID());
				return;
				// TODO Auto-generated catch block
				
			}
		}
	}
	
	// process list request
		private void procListReq(){
			String[] users = ServerMain.getOnlineUsers();
			ListReq req = (ListReq)msg;
			ListReqPlain reqPlain = req.verify(aes, loginAuth.getUser().getUserID());
			if (reqPlain != null){
				ListReply reply = new ListReply(aes, users, reqPlain.getTs() + 1);
				try {
					objout = new ObjectOutputStream(tcpSocket.getOutputStream());
					reply.writeMessage(objout);
					objout.flush();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					return;
				}
				System.out.println("Send list");
			}
		}
		
		// process user to user authentication
		private void procU2UAuth(){
			User2UserAuth1 auth1 = (User2UserAuth1)msg;
			if (auth1 == null){
				return;
			}
			Object obj = Message.bytes2Object(aes.decrypt(auth1.getCipher()));
			U2UAuth1Plain plain1 = (U2UAuth1Plain)obj;
			if(plain1 == null){
				return;
			}
			UserInfo user = ServerMain.searchUser(plain1.getTgtUserId());
			if (user == null){        // dst user does not exist or offline
				return;
			}
			BigInteger rand = Data.randomBigInteger(256);
			byte[] sec = rand.toByteArray();
			AESCrypt aesDst = ServerMain.searchAES(plain1.getTgtUserId());
			TicketPlain ticket = new TicketPlain(sec, sec, plain1.getTgtUserId());
			User2UserAuth2 auth2 = new User2UserAuth2(aes, sec, sec, user, plain1.getNonceSrc(), aesDst.encrypt(ticket.object2Bytes()));
			try {
				objout = new ObjectOutputStream(tcpSocket.getOutputStream());
				auth2.writeMessage(objout);
				objout.flush();
			} catch (IOException e) {
				return;
			}
		}
		
		private void procLogout(){
			LogoutReq req = (LogoutReq)msg;
			long tsAdded = req.verify(aes);
			if (tsAdded == -1){
				return;
			}
			LogoutReply reply = new LogoutReply(aes, tsAdded);
			try {
				objout = new ObjectOutputStream(tcpSocket.getOutputStream());
				reply.writeMessage(objout);
				objout.flush();
			} catch (IOException e) {}
			ServerMain.removeOnlineUser(user.getUserID());
			ServerMain.multicast(user.getUserID());
			
		}
}
