package cs6740.server;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;


import cs6740.conf.PropertiesLoader;
import cs6740.user.UserInfo;
import cs6740.util.AESCrypt;
import cs6740.util.RSACrypt;

public class ServerMain {
	public static final PrivateKey PRIVATE_KEY = RSACrypt.file2RSAPrivateKey("PrivateKey/pri_key.der");
	private ServerSocket serverSocket;
	private DatagramSocket serverUDPSocket;
	private static ServerThreadPool pool;
	public ServerSocket getServerSocket() {
		return serverSocket;
	}

	public void setServerSocket(ServerSocket serverSocket) {
		this.serverSocket = serverSocket;
	}
	
	public static String[] getOnlineUsers(){
		ArrayList<String>users = pool.getOnlineUsers();
		return users.toArray(new String[users.size()]);
	}
	
	public static void addOnlineUser(UserInfo user, AESCrypt aes){
		pool.addOnlineUser(user, aes);
	}
	
	public static void removeOnlineUser(String userID){
		pool.removeOnlineUser(userID);
	}
	
	public static UserInfo searchUser(String userID){
		return pool.searchUser(userID);
	}
	
	public static AESCrypt searchAES(String userID){
		return pool.searchAES(userID);
	}
	
	public static void multicast(String userID){
		pool.logoutNotification(userID);
	}
	
	public static void addToBlacklist(String userID){
		pool.addToBlackList(userID);
	}
	
	public static boolean getFromBlackList(String userID){
		return pool.getFromBlackList(userID);
	}
	
	public static void removeFromBlacklist(String userID){
		pool.removeFromBlackList(userID);
	}
	
	public ServerMain(){
		// initialize sockets
		int tcpPort = Integer.parseInt(PropertiesLoader.getServerProperty("TCPPort"));
		int udpPort = Integer.parseInt(PropertiesLoader.getServerProperty("UDPPort"));
		try {
			System.out.println("Listening on " + tcpPort);
			this.serverSocket = new ServerSocket(tcpPort);
			this.serverUDPSocket = new DatagramSocket(udpPort);
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		// initialize thread pool
		BlockingQueue<Runnable> queue = new ArrayBlockingQueue<Runnable>(10);
		pool = new ServerThreadPool(30, 30, 10000, TimeUnit.MILLISECONDS, queue, serverUDPSocket);
		pool.allowCoreThreadTimeOut(true);
		pool.setRejectedExecutionHandler(new RejectHandler());
		
	}
	
	public void start(){
		while(true){
			try {
				Socket s = serverSocket.accept();
				System.out.println("Got request from " + s.getInetAddress().getHostAddress());
				ServerThread th = new ServerThread(s);
				pool.execute(th);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				continue;
			}
		}
	}
}
