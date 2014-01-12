package cs6740.db;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties; 

import cs6740.util.Data;
import cs6740.util.Hash;
public class DatabaseLoader extends Properties{
	
	/**
	 * Load database storing user credentials 
	 */
	private static final long serialVersionUID = -869916595211700193L;

	public DatabaseLoader(String FileName) throws IOException{
		 InputStream is = new FileInputStream(FileName);
		 //System.out.print("OK");
		 this.load(is);
	}
	
	/*
	 * get password by username
	 */
	public static String getPwd(String userID){
		DatabaseLoader dl;
		try {
			dl = new DatabaseLoader("UserDB/userDB");
			byte[] userIDBytes = Hash.hashMsg(userID.getBytes(), "SHA-1");
			return dl.getProperty(Data.bytes2HexString(userIDBytes));
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return null;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	/*
	 * get salt
	 */
	public static String getSalt(){
		try {
			DatabaseLoader dl = new DatabaseLoader("UserDB/userDB");
			return dl.getProperty("salt");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		
	}
}
