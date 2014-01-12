package cs6740.client;

import java.io.Console;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;


import cs6740.auth.LoginAuthClient;
import cs6740.auth.User2UserAuthSrc;
import cs6740.conf.PropertiesLoader;
import cs6740.msg.Message;
import cs6740.msg.imsg.InstantMessage;
import cs6740.msg.list.ListReply;
import cs6740.msg.list.ListReq;
import cs6740.msg.logout.LogoutReply;
import cs6740.msg.logout.LogoutReq;
import cs6740.server.RejectHandler;
import cs6740.user.UserInfo;
import cs6740.user.UserInfoWithAES;
import cs6740.user.UserMappingValue;
import cs6740.util.AESCrypt;
import cs6740.util.Data;
import cs6740.util.RSACrypt;

/*
 * Main Object of Client program, for making all kind of requests
 * 
 * Author: Guanyu Wang, Xiaoyuan Liu
 */
public class ClientMain {
	private final static int OTHER_AUTH_MAX = 5;
	private final static int U2U_AUTH_MAX = 3;
	public static final PublicKey PUBLIC_KEY = RSACrypt.file2RSAPublicKey("PublicKey/pub_key.der");
    private InetAddress serverAddr;
    private int serverTCPPort;
    private int clientUDPPort;
    private int serverUDPPort;
    private int clientTCPPort;
    private Socket tcpSocket;
    private ObjectInputStream objin;
    private ObjectOutputStream objout;
    private DatagramSocket udpSocket;
    private ServerSocket listeningSocket;
    private ClientListeningAuth listeningTh;
    private ClientRecvThread recvTh;
    private Console cons;
    private AESCrypt aes;
    private String userID;
    private long ts;
    private String[] usersList;
    public static ClientThreadPool pool;
    private static Hashtable<String, UserInfoWithAES> onlineUsers;
	private static Hashtable<Long, UserMappingValue> userMappings;
    
    /*
     *  initialize UDP socket
     */
    private void initUDP(){
    	for (int start = clientUDPPort; start < clientUDPPort + 1000; start ++){
	    	try {
				udpSocket = new DatagramSocket(start);
				clientUDPPort = start;
				return;
			} catch (SocketException e) {
				// TODO Auto-generated catch block
			}
    	}
    	System.out.println("UDP Port not available!");
    	System.exit(0);
    }
    
    /*
     *  initialize TCP socket for listening user-to-user authentication
     */
    private void initListeningTCP(){
    	for (int start = clientTCPPort; start < clientTCPPort + 1000; start ++){
	    	try {
				listeningSocket = new ServerSocket(start);
				clientTCPPort = start;
				return;
			} catch (SocketException e) {}
	    	catch (IOException e) {}
    	}
    	System.out.println("TCP Port not available!");
    	System.exit(0);
    }
    
    public static void addThreadIntoPool(Thread t){
    	pool.execute(t);
    }
    
    /*
     *  initialize main thread of client, make login authentication request
     */
    public boolean init(String userID, String pwd, Console cons){
    	this.cons = cons;
    	System.out.println(loadProperties());
    	BlockingQueue<Runnable> queue = new ArrayBlockingQueue<Runnable>(10);
    	pool = new ClientThreadPool(30, 30, 10000, TimeUnit.MILLISECONDS, queue);
		pool.allowCoreThreadTimeOut(true);
		pool.setRejectedExecutionHandler(new RejectHandler());
		this.userID = userID;
		initUDP();
		initListeningTCP();
		onlineUsers = new Hashtable<String, UserInfoWithAES>();
		userMappings = new Hashtable<Long, UserMappingValue>();
		
		/*
		 *  make authentication 10 times
		 */
		try {
    		int count = 0;
    		while (count < OTHER_AUTH_MAX){
    			count ++;
    			//System.out.println("Start creating socket");
    			tcpSocket = new Socket(serverAddr, serverTCPPort);
    			
    			System.out.println("Trying authentication...");
    			LoginAuthClient auth = new LoginAuthClient(tcpSocket);
    			int ret = auth.makeRequest(userID, pwd, clientUDPPort, clientTCPPort);
    			if (ret == LoginAuthClient.SUCCESS){
    				cons.printf("Authentication approved!\n");
    				this.aes = auth.getAes();
    				return true;
    			}
    			else if (ret == LoginAuthClient.PWD_ERR){
    				cons.printf("User ID or password incorrect!\n");
    				System.exit(0);
    			}
    			else if (ret == LoginAuthClient.BLK_ERR){
    				cons.printf("User blocked, try logging in 30 minutes later!\n");
    				System.exit(0);
    			}
    			else if (ret == LoginAuthClient.DUP_LOGIN){
    				cons.printf("You have already logged in.!\n");
    				System.exit(0);
    			}
    			else{
    				tcpSocket.close();
    			}
    		}
    		return false;
		} catch (IOException e) {
			//e.printStackTrace();
			System.out.println("Server unavailable. Please try again!");
			return false;
		}
    }
    
    
	private boolean loadProperties(){
		String addrStr = PropertiesLoader.getClientProperty("ServerIPAddress");
		String tcpPortStr = PropertiesLoader.getClientProperty("ServerTCPPort");
		String udpPortServer = PropertiesLoader.getClientProperty("ServerUDPPort");
		String udpPortStr = PropertiesLoader.getClientProperty("ClientUDPPort");
		String ltnPortStr = PropertiesLoader.getClientProperty("ClientTCPPort");

		try {
			this.serverAddr = InetAddress.getByName(addrStr);
			this.serverTCPPort = Integer.parseInt(tcpPortStr);
			this.serverUDPPort = Integer.parseInt(udpPortServer);
			this.clientUDPPort = Integer.parseInt(udpPortStr);
			this.clientTCPPort = Integer.parseInt(ltnPortStr);
			return true;
		} catch (UnknownHostException e) {
			e.printStackTrace();
			return false; 
		}
	}
	
	public void start(){
		String msg = "";
		listeningTh = new ClientListeningAuth(listeningSocket,  aes, userID);
		recvTh = new ClientRecvThread(udpSocket, cons, serverAddr, serverUDPPort, aes);
		listeningTh.start();
		recvTh.start();
		while(true){
			msg = cons.readLine();
			
			if (msg.equals("list")){
				procList();
			}
			else if(msg.startsWith("send ")){
				procCommunication(msg);
			}
			else if (msg.equals("logout")){
				boolean ret = procLogout();
				if (ret){
					System.out.println("logout successfully!");
					System.exit(0);
				}
			}
			else{
				continue;
			}
			try {
				tcpSocket.setSoTimeout(0);
			} catch (SocketException e) {
				// TODO Auto-generated catch block
				continue;
			}
		}
	}
	
	/*
	 *  send message via UDP 
	 */
	private void sendMsgUDP(UserInfoWithAES user, InstantMessage im){
		//System.out.println("Build msg");
		byte[] data = im.object2Bytes();
		DatagramPacket dPacket = new DatagramPacket(data, data.length, user.getAddr(), user.getUdpPort());
		try {
			udpSocket.send(dPacket);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/*
	 *  send message via TCP
	 */
	private void sendMsgTCP(Message msg){
		try {
			this.objout = new ObjectOutputStream(tcpSocket.getOutputStream());
			msg.writeMessage(objout);
			objout.flush();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/*
	 *  process inputs from console
	 */
	private void procCommunication(String msg){
		String[] msgSplit = msg.split(" ");
		if (msgSplit.length < 3){
			cons.printf("Message format: SEND <userID> Message\n");
			return;
		}
		String dstUserID = msgSplit[1];
		//System.out.println(dstUserID);
		UserInfoWithAES dstUser = searchUser(dstUserID);
		boolean ret = false;
		if (dstUser == null){
			for (int count = 0; count < U2U_AUTH_MAX; count ++){
				User2UserAuthSrc auth = new User2UserAuthSrc(tcpSocket, aes);
				ret = auth.commandRequest(userID, dstUserID, clientUDPPort, clientTCPPort);
				if (ret) {
					dstUser = searchUser(dstUserID);
					break;
				}
			}
			if (!ret){
				cons.printf("Authentication to %s failed!\n", dstUserID);
				return;
			} 
		}
		String text = msg.substring("send".length() + dstUserID.length() + 1, msg.length());
		InstantMessage im = new InstantMessage(text, dstUser.getAes());
		sendMsgUDP(dstUser, im); 
	}
	
	/*
	 *  process list request
	 */
	private void procList(){
		int count = 0;
		while (count < OTHER_AUTH_MAX){
			count ++;
			ts = Data.timestamp();
			ListReq req = new ListReq(aes, userID, ts);
			Object msg;
			try {
				sendMsgTCP(req);
				this.objin = new ObjectInputStream(tcpSocket.getInputStream());				
				msg = Message.readAnObject(objin);
				if (msg.getClass().equals(ListReply.class)){
					System.out.println("Got list");
					ListReply reply = (ListReply)msg;
					usersList = reply.verify(aes, ts);
					if (usersList == null){
						continue;
					}
					for (int n = 0; n < usersList.length; n ++){
						cons.printf("%s\n", usersList[n]);
					}
					return;
				}
			} catch (ClassNotFoundException e) {
				continue;
			} catch (IOException e) {
				continue;
			}
		}
		cons.printf("Fail to request list of users, please try again!\n");
	}
	
	/*
	 * process logout
	 */
	private boolean procLogout(){
		for (int count = 0; count < OTHER_AUTH_MAX; count ++){
			long ts = Data.timestamp();
			LogoutReq req = new LogoutReq(aes, ts);
			sendMsgTCP(req);
			try{
				this.objin = new ObjectInputStream(tcpSocket.getInputStream());
				Object msg;
				msg = Message.readAnObject(objin);
				if (msg.getClass().equals(LogoutReply.class)){
					System.out.println("Got logout reply");
					LogoutReply reply = (LogoutReply)msg;
					boolean ret = reply.verify(aes, ts);
					if (ret) {return true;}
				}
			}catch (IOException e){
				continue;
			} catch (ClassNotFoundException e) {
				continue;
			}
		}
		return false;
	}

	/*
	 * Add an online user into tables
	 */
	public static synchronized void addOnlineUser(UserInfo user, AESCrypt aes){
		onlineUsers.put(user.getUserID(), user.toChild(aes));
	}
	
	/*
	 * remove an online user from table
	 */
	public static synchronized void removeOnlineUser(String userID){
		if (onlineUsers.get(userID) != null){
			onlineUsers.remove(userID);
		}
	}
	
	/*
	 * Search user from table
	 */
	public static UserInfoWithAES searchUser(String userID){
		UserInfoWithAES user = onlineUsers.get(userID);
		if (user == null){
			return null;
		}
		return user;
	}
	
	/*
	 * Search AES from table
	 */
	public static AESCrypt searchAES(String userID){
		UserInfoWithAES user = onlineUsers.get(userID);
		if (user == null){
			return null;
		}
		return user.getAes();
	}
	
	/*
	 * get the list of online users from local table(not server)
	 */
	public static ArrayList<String> getOnlineUsers(){
		ArrayList<String>users = new ArrayList<String>();
		Enumeration<String>keys = onlineUsers.keys();
		while (keys.hasMoreElements()){
			users.add(keys.nextElement());
		}
		return users;
	}
	
	/*
	 * search user by address and port
	 */
	public static UserMappingValue searchUserByInetInfo(Long key){
		return userMappings.get(key);
	}
	
	/*
	 *  add user to user mapping table
	 */
	public static synchronized void addToMappings(Long key, UserMappingValue value){
		userMappings.put(key, value);
	}
	
	/*
	 * remove user from user mapping table
	 */
	public static synchronized void removeMapping(Long key){
		if (userMappings.get(key) != null){
			userMappings.remove(key);
		}
	}
}
