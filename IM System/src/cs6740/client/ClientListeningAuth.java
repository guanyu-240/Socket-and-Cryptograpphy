package cs6740.client;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

import cs6740.util.AESCrypt;

/*
 * Thread for client listening for user to user authentication,
 * create a new thread after receiving TCP connection
 * 
 * Author: Guanyu Wang, Xiaoyuan Liu
 */
public class ClientListeningAuth extends Thread{
	private ServerSocket socket;
	private AESCrypt aes;
	private String userID;
	
	/**
	 * @param args
	 */
	
	public ClientListeningAuth(ServerSocket socket, AESCrypt aes, String userID){
		this.socket = socket;
		this.aes = aes;
		this.userID = userID;
	}
	public void run(){
		while (true){
			try {
				Socket s = socket.accept();
				ClientAuthThread authTh = new ClientAuthThread(s,  aes, userID);
				ClientMain.addThreadIntoPool(authTh);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				continue;
			}
		}
	}
}
