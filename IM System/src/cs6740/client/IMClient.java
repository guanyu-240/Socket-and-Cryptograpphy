package cs6740.client;


import java.io.Console;
import java.io.IOException;

/*
 * Main class of Client Program
 * 
 * Author: Guanyu Wang, Xiaoyuan Liu
 */
public class IMClient {
	/**
	 * @param args
	 * @throws IOException 
	 */
	
	public static void main (String[] args) throws IOException{
		ClientMain client = new ClientMain();
		String userID;
		char[] PWD;
		Console cons;
		if ((cons = System.console())!=null){
				System.out.println("User ID:");
			    userID = cons.readLine();
				System.out.println("Password:");
				PWD = cons.readPassword();
				client.init(userID, new String(PWD), cons);
				client.start();
		}
	
	}
	

}
