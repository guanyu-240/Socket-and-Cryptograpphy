package cs6740.auth;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.net.SocketException;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;


import cs6740.msg.Message;
import cs6740.msg.loginAuth.*;
import cs6740.user.UserInfo;
import cs6740.util.AESCrypt;
import cs6740.util.DHExchange;
import cs6740.util.Data;
import cs6740.util.Hash;
import cs6740.util.Keys;

/*
 * Object for login authentication on the client side
 * 
 * Author: Guanyu Wang,  Xiaoyuan liu
 */
public class LoginAuthClient {
	public static final String PWD_ERR_MSG = "WRONG_USERNAME_OR_PWD";
	public static final String BLACK_LISTED = "BLACKLISTED";
	public static final String ALREADY_LOGGED_IN = "ALREADY_LOGGED_IN";
	public static final int SUCCESS = 0;
	public static final int PWD_ERR = -1;
	public static final int BLK_ERR = -2;
	public static final int DUP_LOGIN = -3;
	public static final int OTHER_ERR = -5;
	private DHExchange dh;
	private BigInteger r2;
	private byte[] hashedPwd;
	private Socket tcpSocket;
	private ObjectInputStream objin;
	private ObjectOutputStream objout;
	private AESCrypt aes;
	public LoginAuthClient(Socket tcpSocket){
		this.tcpSocket = tcpSocket;
		try {
			tcpSocket.setSoTimeout(5000);
		} catch (SocketException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		dh = new DHExchange();
	}
	
	public ObjectInputStream getObjin(){
		return this.objin;
	}
	
	/*
	 *  receive Message
	 */
	private Object receiveMsg(Object obj){
		Object msg;
		try {
			objin = new ObjectInputStream(tcpSocket.getInputStream());
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
	
	/*
	 *  send message via TCP channel
	 */
	private void sendMsg(Message msg){
		try {
			this.objout = new ObjectOutputStream(tcpSocket.getOutputStream());
			msg.writeMessage(objout);
			objout.flush();
		} catch (IOException e) {
			return;
		}
	}
	
	// make request;
	public int makeRequest(String userID, String pwd, int udpPort, int listeningPort) throws IOException{
		Object msg = null;
		LoginRequest req = new LoginRequest();
		sendMsg(req);
			
		// initialize input stream
		msg = receiveMsg(LoginAuth2.class);
		if (msg == null){
			return OTHER_ERR;
		}
		LoginAuth3 login3 = msgProcLoginAuth2((LoginAuth2)msg, userID, pwd, udpPort, listeningPort);
		if (login3 == null){
			return OTHER_ERR;
		}

		sendMsg(login3);
		msg = receiveMsg(LoginAuth4.class);
		if (msg == null){
			return OTHER_ERR;
		}
		LoginAuth5 login5 = msgProcLoginAuth4((LoginAuth4)msg);
		if (login5 == null){
			return OTHER_ERR;
		}
		
		if (login5.getCipher() == null){
			return BLK_ERR;
		}
		if (login5.getCipher().length == 0){
			return PWD_ERR;
		}
		if (login5.getCipher().length == 1){
			return DUP_LOGIN;
		}
		sendMsg(login5);
		return SUCCESS; // Authentication approved
	}

	/*
	 *  process LoginAuth2
	 */
	public LoginAuth3 msgProcLoginAuth2(LoginAuth2 login2, String userID, String pwd, int udpPort, int listeningPort){
		if (!login2.signatureVerify()){
			System.out.println("Signature verification error");
		}
		int answer = login2.solve();
		if (answer == -1){
			return null;
		}
		LoginAuth3 login3 = new LoginAuth3();
		r2 = Data.randomBigInteger(256);
		dh.genKeyPair();
		hashedPwd = Hash.hashPasswd(pwd, login2.getSalt());
		UserInfo user = new UserInfo(userID, tcpSocket.getLocalAddress(), udpPort, listeningPort);
		login3.init(user, r2, dh.getDHPublic().getEncoded(), hashedPwd, answer);
		return login3;
	}
	
	/*
	 *  process LoginAuth4
	 */
	public LoginAuth5 msgProcLoginAuth4(LoginAuth4 login4){
		byte[] secretNew = Data.mergeBytes(r2.toByteArray(), hashedPwd);
		SecretKey key = Keys.genKeyFromSecret(secretNew);
		IvParameterSpec iv = Keys.genIVFromSecret(secretNew);
		LoginAuth4Ret ret =login4.verify(r2, dh, key, iv);
		if (ret == null){
			return null;
		}
		else if (ret.getResult() == LoginAuth4Ret.BLOCKED){
			return new LoginAuth5();
		}
		else if (ret.getResult() == LoginAuth4Ret.WRONG){
			LoginAuth5 auth5 =  new LoginAuth5();
			auth5.setCipher(new byte[0]);
			return auth5;
		}
		else if (ret.getResult() == LoginAuth4Ret.ALREADY_LOGGED_IN){
			LoginAuth5 auth5 = new LoginAuth5();
			auth5.setCipher(new byte[1]);
			return auth5;
		}
		dh = ret.getDh();
		int r3 = ret.getR3();
		aes = dh.getAes();
		LoginAuth5 login5 = new LoginAuth5(r3, aes);
		return login5;
	}

	public AESCrypt getAes() {
		return aes;
	}

}
