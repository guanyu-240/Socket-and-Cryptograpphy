package cs6740.msg.loginAuth;
import java.math.BigInteger;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import cs6740.auth.LoginAuthClient;
import cs6740.client.ClientMain;
import cs6740.msg.Message;
import cs6740.server.ServerMain;
import cs6740.util.AESCrypt;
import cs6740.util.DHExchange;
import cs6740.util.Data;
import cs6740.util.RSACrypt;

/**
 * Class of 4th message in login authentication
 * 
 * @author Guanyu Wang, Xiaoyuan Liu
 *
 */
public class LoginAuth4 extends Message {
	/**
	 * 
	 */
	private static final long serialVersionUID = 3647941039513207352L;
	private byte[] cipher1;
	private byte[] cipher2;
	private byte[] signature;
	public LoginAuth4(byte[] cipher1, DHExchange dh, BigInteger r2, int r3){
		this.cipher1 = cipher1;
		AESCrypt aes = dh.getAes();
		LoginAuth4Plain login4plain = new LoginAuth4Plain(r2, r3);
		this.cipher2 = aes.encrypt(login4plain.object2Bytes());
		RSACrypt rsa = new RSACrypt(ServerMain.PRIVATE_KEY);
		this.signature = rsa.sign(Data.mergeBytes(cipher1, cipher2));
	}

	public byte[] getCipher1() {
		return cipher1;
	}
	public void setCipher1(byte[] cipher1) {
		this.cipher1 = cipher1;
	}
	public byte[] getCipher2() {
		return cipher2;
	}
	public void setCipher2(byte[] cipher2) {
		this.cipher2 = cipher2;
	}
	public byte[] getSignature() {
		return signature;
	}
	public void setSignature(byte[] signature) {
		this.signature = signature;
	}
	
	
	/*
	 *  verify the message
	 */
	public LoginAuth4Ret verify(BigInteger r2, DHExchange dh, SecretKey key, IvParameterSpec iv){
		if (!dh.isReadyForAgreement()){
			return null;
		}
		if (!signatureVerify()){
			System.out.println("Signature verification error");
			return null;
		}
		LoginAuth4Ret ret = new LoginAuth4Ret();
		ret.setResult(LoginAuth4Ret.CORRECT);
		AESCrypt aes = new AESCrypt(key, iv);
		byte[] pubKeyBytes = aes.decrypt(cipher1);
		if (Arrays.equals(pubKeyBytes, LoginAuthClient.PWD_ERR_MSG.getBytes())){
			ret.setResult(LoginAuth4Ret.WRONG);
			return ret;
		}
		else if (Arrays.equals(pubKeyBytes, LoginAuthClient.BLACK_LISTED.getBytes())){
			ret.setResult(LoginAuth4Ret.BLOCKED);
			return ret;
		}
		else if (Arrays.equals(pubKeyBytes, LoginAuthClient.ALREADY_LOGGED_IN.getBytes())){
			ret.setResult(LoginAuth4Ret.ALREADY_LOGGED_IN);
			return ret;
		}
		dh.genSecKey(pubKeyBytes);
		aes = dh.getAes();
		LoginAuth4Plain auth4 = (LoginAuth4Plain)bytes2Object(aes.decrypt(cipher2));
		BigInteger r2Added = auth4.getR2Added();
		if (!r2Added.equals(r2.add(BigInteger.ONE))){
			return null;
		}
		int r3 = auth4.getR3();
		ret.setDh(dh);
		ret.setR3(r3);
		return ret;
	}
	
	private boolean signatureVerify(){
		RSACrypt rsa = new RSACrypt(ClientMain.PUBLIC_KEY);
		return rsa.verify(Data.mergeBytes(cipher1, cipher2), signature);
	}
	
	public class LoginAuth4Plain extends Message{
		/**
		 * 
		 */
		private static final long serialVersionUID = -3001015480069473257L;
		private BigInteger r2Added;
		private int r3;
		public LoginAuth4Plain(BigInteger r2, int r3){
			r2Added = r2.add(BigInteger.ONE);
			this.r3 = r3;
		}
		public BigInteger getR2Added() {
			return r2Added;
		}
		public void setR2Added(BigInteger r2Added) {
			this.r2Added = r2Added;
		}
		public int getR3() {
			return r3;
		}
		public void setR3(int r3) {
			this.r3 = r3;
		}
	}
}
