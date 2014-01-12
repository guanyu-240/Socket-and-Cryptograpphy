package cs6740.server;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;


import cs6740.msg.imsg.InstantMessage;
import cs6740.user.UserInfo;
import cs6740.user.UserInfoWithAES;
import cs6740.util.AESCrypt;
import cs6740.util.Data;

public class ServerThreadPool extends ThreadPoolExecutor{
	private Hashtable<String, UserInfoWithAES> onlineUsers;
	private Hashtable<String, Long>blacklist;
	private DatagramSocket serverUDPSocket;
	private static final int MAX_LOGIN = 5;
	private static final long DELAY = 1800000;
	public ServerThreadPool(int corePoolSize, int maximumPoolSize,
			long keepAliveTime, TimeUnit unit, BlockingQueue<Runnable> workQueue, DatagramSocket serverUDPSocket) {
		super(corePoolSize, maximumPoolSize, keepAliveTime, unit, workQueue);
		onlineUsers = new Hashtable<String, UserInfoWithAES>();
		blacklist = new Hashtable<String, Long>();
		this.serverUDPSocket = serverUDPSocket;
	}
	
	/*
	 *  add an online user
	 */
	public synchronized void addOnlineUser(UserInfo user, AESCrypt aes){
		if (onlineUsers.get(user) == null){
			onlineUsers.put(user.getUserID(), user.toChild(aes));
		}
	}
	
	/*
	 *  remove an online user
	 */
	public synchronized void removeOnlineUser(String userID){
		if (onlineUsers.get(userID) != null){
			onlineUsers.remove(userID);
		}
	}
	
	/*
	 *  search user
	 */
	public synchronized UserInfo searchUser(String userID){
		UserInfoWithAES user = onlineUsers.get(userID);
		if (user == null){
			return null;
		}
		return user.toSuper();
	}
	
	/*
	 *  search key agreed by server and specified user
	 */
	public synchronized AESCrypt searchAES(String userID){
		UserInfoWithAES user = onlineUsers.get(userID);
		if (user == null){
			return null;
		}
		return user.getAes();
	}
	
	/*
	 * get list of online users
	 */
	public synchronized ArrayList<String> getOnlineUsers(){
		ArrayList<String>users = new ArrayList<String>();
		Enumeration<String>keys = onlineUsers.keys();
		while (keys.hasMoreElements()){
			users.add(keys.nextElement());
		}
		return users;
	}
	
	/*
	 *  when a user logs out, server notify this to all the users
	 */
	public void logoutNotification(String userID){
		Collection<UserInfoWithAES>values = onlineUsers.values();
		int size = values.size();
		UserInfoWithAES[] users = values.toArray(new UserInfoWithAES[size]);
		for (int n = 0; n < size; n ++){
			InstantMessage msg = new InstantMessage(userID, users[n].getAes());
			byte[] data = msg.object2Bytes();
			DatagramPacket packet = new DatagramPacket(data, data.length, users[n].getAddr(), users[n].getUdpPort());
			try {
				serverUDPSocket.send(packet);
			} catch (IOException e) {
				continue;
			}
		}
	}
	
	public synchronized void addToBlackList(String userID){
		if (blacklist.get(userID) == null){
			blacklist.put(userID, (long) 1);
		}
		else{
			long times = blacklist.get(userID);
			if (times < MAX_LOGIN){
				blacklist.put(userID, (times + 1));
			}
			else{
				long ts = Data.timestamp() + DELAY;
				blacklist.put(userID, ts);
			}
		}
	}
	
	public synchronized boolean getFromBlackList(String userID){
		Long value = blacklist.get(userID);
		if (value == null){
			return false;
		}
		else if (value < MAX_LOGIN){
			return false;
		}
		else if(value > Data.timestamp()){
			blacklist.remove(userID);
			return false;
		}
		return true;
	}
	
	public synchronized void removeFromBlackList(String userID){
		if (blacklist.get(userID) != null){
			blacklist.remove(userID);
		}
	}
}
