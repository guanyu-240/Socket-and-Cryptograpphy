package cs6740.msg.loginAuth;
import java.math.BigInteger;
import java.net.InetAddress;
import java.util.Arrays;

import cs6740.client.ClientMain;
import cs6740.db.DatabaseLoader;
import cs6740.msg.Message;
import cs6740.server.ServerMain;
import cs6740.user.UserInfo;
import cs6740.util.Data;
import cs6740.util.Hash;
import cs6740.util.RSACrypt;

/*
 * 3rd message in the process of login authentication
 * 
 * Author: Guanyu Wang, Xiaoyuan Liu
 */
public class LoginAuth3 extends Message {

	/**
	 * 
	 */
	private static final long serialVersionUID = -935932158298538173L;
	private byte[] cipher;
	private int r1;
	private byte[] hmacValue; 
	
	/*
	 * Initialize the message
	 */
	public void init(UserInfo user, BigInteger r2,byte[] DHcontri,byte[] hashPWDandSalt, int answer){
		
		LoginAuth3Plain plainInfo = new LoginAuth3Plain(user, r2, DHcontri, hashPWDandSalt); //create a innerClass object
		byte[] plainInfoBytes = plainInfo.object2Bytes();  //serialize the inner class into byte[]
		if (ClientMain.PUBLIC_KEY == null){
			System.out.println("Public key error! Please check public key file.");
			System.exit(-1);
		}
		RSACrypt rsaCryptor = new RSACrypt(ClientMain.PUBLIC_KEY);			
		byte[] chipherInfoBytes = rsaCryptor.crypt(plainInfoBytes); //encrypt inner class
		this.cipher = chipherInfoBytes;								  //set ciphertext
		this.r1 = answer;													  //set random number R1
		this.hmacValue = Hash.hmacMsg(hashPWDandSalt, this.cipher);				  // compute the hmac of the message
	}
	
	public boolean checkAnswer(int challenge){
		if (this.r1 == challenge){
			return true;
		}
		else {
			return false;
		}
	}
	
	/*
	 * Verification of LoginAuth3
	 */
	public LoginAuth3Ret verify(InetAddress addr){
		RSACrypt rsa = new RSACrypt(ServerMain.PRIVATE_KEY);
		LoginAuth3Plain login3 = (LoginAuth3Plain)bytes2Object(rsa.crypt(cipher));
		LoginAuth3Ret ret = new LoginAuth3Ret(login3);
		ret.setResult(LoginAuth3Ret.CORRECT);
		String userID = login3.getUser().getUserID();
		byte[] pwd = login3.getHashPWDandSalt();
		String pwdHexStr = Data.bytes2HexString(pwd);
		// check hmac
		if (!Arrays.equals(Hash.hmacMsg(pwd, this.cipher), this.hmacValue)){
			System.out.println("HMAC check error");
			return null;
		}
		if (ServerMain.searchUser(userID) != null){
			ret.setResult(LoginAuth3Ret.ALREADY_LOGGED_IN);
		}
		// check if user is blocked 
		else if (ServerMain.getFromBlackList(userID)){
			ret.setResult(LoginAuth3Ret.BLOCKED);
		}
		// check password
		else if (!DatabaseLoader.getPwd(userID).equals(pwdHexStr)){
			ret.setResult(LoginAuth3Ret.WRONG);
			ServerMain.addToBlacklist(userID);
		}
		ServerMain.removeFromBlacklist(userID);
		return ret;
	}
	
	/*
	 * Plain message of LoginAuth3
	 */
	public class LoginAuth3Plain extends Message{
		
		private static final long serialVersionUID = -935932158298538173L;
		
		private UserInfo user;
		private BigInteger r2;
		private byte[] dhPublic;
		private byte[] hashPWDandSalt;
		public LoginAuth3Plain(){}
		public LoginAuth3Plain(UserInfo user, BigInteger r2, byte[] dhPublic, byte[] hashedPwd){
			this.user = user;
			this.r2 = r2;
			this.dhPublic = dhPublic;
			this.hashPWDandSalt = hashedPwd;
		}

		public UserInfo getUser() {
			return user;
		}
		public void setUser(UserInfo user) {
			this.user = user;
		}
		public BigInteger getR2() {
			return r2;
		}
		public void setR2(BigInteger r2) {
			this.r2 = r2;
		}
		public byte[] getdhPublic() {
			return dhPublic;
		}
		public void setdhPublic(byte[] dhPublic) {
			this.dhPublic = dhPublic;
		}
		public byte[] getHashPWDandSalt() {
			return hashPWDandSalt;
		}
		public void setHashPWDandSalt(byte[] hashPWDandSalt) {
			this.hashPWDandSalt = hashPWDandSalt;
		}
	}
}
