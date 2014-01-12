package cs6740.user;


import cs6740.util.AESCrypt;

public class UserMappingValue{
	private String userID;
	private AESCrypt aes;
	public UserMappingValue(String userID, AESCrypt aes){
		this.userID = userID;
		this.aes = aes;
	}
	public String getUserID() {
		return userID;
	}
	public void setUserID(String userID) {
		this.userID = userID;
	}
	public AESCrypt getAes() {
		return aes;
	}
	public void setAes(AESCrypt aes) {
		this.aes = aes;
	}

}
