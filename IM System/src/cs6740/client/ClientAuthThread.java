package cs6740.client;

import java.net.Socket;


import cs6740.auth.User2UserAuthDst;
import cs6740.util.AESCrypt;

/*
 *  User to user authentication thread, created when user get tcp
 *  connection of other users
 *  
 *  Author: Guanyu Wang, Xiaoyuan Liu
 */
public class ClientAuthThread extends Thread{
	private Socket tcpSocket;
	private AESCrypt aes;
	private String userID;
	public ClientAuthThread(Socket tcpSocket, AESCrypt aes, String userID){
		this.tcpSocket = tcpSocket;
		this.aes = aes;
		this.userID = userID;
	}
	public void run(){
		User2UserAuthDst auth = new User2UserAuthDst(tcpSocket, aes, userID);
		auth.procAuth();
	}
}
