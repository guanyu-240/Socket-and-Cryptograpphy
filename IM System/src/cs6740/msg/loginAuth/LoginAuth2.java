package cs6740.msg.loginAuth;
import cs6740.client.ClientMain;
import cs6740.db.DatabaseLoader;
import cs6740.msg.Message;
import cs6740.server.ServerMain;
import cs6740.util.Data;
import cs6740.util.Hash;
import cs6740.util.RSACrypt;

/**
 * Class of 2nd message in login authentication
 * 
 * @author Guanyu Wang, Xiaoyuan Liu
 *
 */
public class LoginAuth2 extends Message {

	/**
	 * 
	 */

	
	private static final long serialVersionUID = 7532346582854262158L;
	private byte[] hashValue;
	private String salt;
	private int    length;
	private byte[] signature;
	/**
	 * 
	 * @param salt
	 * @param r1
	 * @initiate r1 and salt in this message.
	 */
	
	public LoginAuth2 (int length, int number){
		
		this.length = length;
		salt = DatabaseLoader.getSalt();
		byte[] combine = Data.mergeBytes(Data.int2Bytes(number), salt.getBytes());
		hashValue = Hash.hashMsg(combine, "SHA-1");
		RSACrypt rsa = new RSACrypt(ServerMain.PRIVATE_KEY);
		byte[] data = Data.mergeBytes(hashValue, salt.getBytes());
		data = Data.mergeBytes(data, Data.int2Bytes(length));
		this.signature = rsa.sign(data);
	}

	public boolean signatureVerify(){
		RSACrypt rsa = new RSACrypt(ClientMain.PUBLIC_KEY);
		byte[] data = Data.mergeBytes(hashValue, salt.getBytes());
		data = Data.mergeBytes(data, Data.int2Bytes(length));
		return rsa.verify(data, signature);
	}
	
	public byte[] getHashValue() {
		return hashValue;
	}
	public void setHashValue(byte[] hashValue) {
		this.hashValue = hashValue;
	}
	public String getSalt() {
		return salt;
	}
	public void setSalt(String salt) {
		this.salt = salt;
	}
	public int getLength() {
		return length;
	}
	public void setLength(int length) {
		this.length = length;
	}
	public byte[] getSignature() {
		return signature;
	}
	public void setSignature(byte[] signature) {
		this.signature = signature;
	}
	public int solve(){
		return Data.solveChallenge(length, hashValue, salt.getBytes());
	}
}
