package cs6740.auth;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.SocketException;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;


import cs6740.msg.Message;
import cs6740.msg.loginAuth.LoginAuth2;
import cs6740.msg.loginAuth.LoginAuth3;
import cs6740.msg.loginAuth.LoginAuth3Ret;
import cs6740.msg.loginAuth.LoginAuth4;
import cs6740.msg.loginAuth.LoginAuth5;
import cs6740.msg.loginAuth.LoginRequest;
import cs6740.msg.loginAuth.LoginAuth3.LoginAuth3Plain;
import cs6740.user.UserInfo;
import cs6740.util.AESCrypt;
import cs6740.util.DHExchange;
import cs6740.util.Data;
import cs6740.util.Keys;

/*
 * Object for login authentication on the server side
 */
public class LoginAuthServer extends Thread{

	/**
	 * @param args
	 */
	public static final String PWD_ERR_MSG = "WRONG_USERNAME_OR_PWD";
	public static final String BLACK_LISTED = "BLACKLISTED";
	public static final String ALREADY_LOGGED_IN = "ALREADY_LOGGED_IN";
	private Socket tcpSocket;
	private ObjectInputStream objin;
	private ObjectOutputStream objout;
	private int challenge;
	private DHExchange dh;
	private AESCrypt aes;
	private UserInfo user;
	private int r3;

	
	public DHExchange getDh() {
		return dh;
	}

	public void setDh(DHExchange dh) {
		this.dh = dh;
	}
	
	public AESCrypt getAes() {
		return aes;
	}

	public void setAes(AESCrypt aes) {
		this.aes = aes;
	}
	
	/*
	 * construct method
	 */
	public LoginAuthServer(Socket tcpSocket){
		this.tcpSocket = tcpSocket;
		try {
			tcpSocket.setSoTimeout(1000);
		} catch (SocketException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/*
	 *  receive message via TCP channel
	 */
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
			// TODO Auto-generated catch block
			System.out.println("Class change detected!");
			System.out.println("Thread will end");
			return null;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("Thread will end");
			return null;
		}
			
	}
	
	/*
	 * send message via TCP channel
	 */
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
	
	/*
	 * process login authentication
	 */
	public boolean procLoginAuth(){
		Object msg = null;
		msg = receiveMsg(LoginRequest.class);
		if (msg == null){
			return false;
		}
		challenge = procLoginReq();
		msg = receiveMsg(LoginAuth3.class);
		if (msg == null){
			return false;
		}
		LoginAuth4 login4 = procLoginAuth3((LoginAuth3)msg);
		if (login4 == null){
			return false;
		}
		sendMsg(login4);
		msg = receiveMsg(LoginAuth5.class);
		if (msg == null){
			return false;
		}
		return ((LoginAuth5)msg).verify(r3, aes);
	}
	
	/*
	 *  process login request
	 */
	private int procLoginReq(){
		int length = Math.min(Data.randomNumber(4), 12);
		int number = Data.randomNumber(length);
		LoginAuth2 login2 = new LoginAuth2(length, number);
		sendMsg(login2);
		return number;
	}
	
	/*
	 *  process LoginAuth4
	 */
	private LoginAuth4 procLoginAuth3(LoginAuth3 login3){
		if (login3.checkAnswer(challenge) == false){
			return null;
		}
		LoginAuth3Ret verifyRet = login3.verify(tcpSocket.getInetAddress());
		LoginAuth3Plain plain = verifyRet.getLogin3();
		if (plain == null){
			return null;
		}
		this.user = plain.getUser();
		dh = new DHExchange();
		byte[] dhPubBytes = dh.genKeyPair();
		dh.genSecKey(plain.getdhPublic());
		byte[] secret = Data.mergeBytes(plain.getR2().toByteArray(), plain.getHashPWDandSalt());
		SecretKey key = Keys.genKeyFromSecret(secret);
		IvParameterSpec iv = Keys.genIVFromSecret(secret);
		aes = new AESCrypt(key, iv);
		byte[] cipher1 = null;
		switch (verifyRet.getResult()){
			case LoginAuth3Ret.CORRECT:
				cipher1 = aes.encrypt(dhPubBytes);
				break;
			case LoginAuth3Ret.WRONG:
				cipher1 = aes.encrypt(PWD_ERR_MSG.getBytes());
				break;
			case LoginAuth3Ret.BLOCKED:
				cipher1 = aes.encrypt(BLACK_LISTED.getBytes());
				break;
			case LoginAuth3Ret.ALREADY_LOGGED_IN:
				cipher1 = aes.encrypt(ALREADY_LOGGED_IN.getBytes());
				break;
		}
		aes = dh.getAes();
		r3 = Data.randomNumber(16);
		LoginAuth4 login4 = new LoginAuth4(cipher1, dh, plain.getR2(), r3);
		return login4;
	}

	public Socket getTcpSocket() {
		return tcpSocket;
	}

	public void setTcpSocket(Socket tcpSocket) {
		this.tcpSocket = tcpSocket;
	}

	public UserInfo getUser() {
		return user;
	}

	public void setUser(UserInfo user) {
		this.user = user;
	}

	
	
}
