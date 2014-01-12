/* fcrypt - Main class to run the encrypt/decrypt program
 * To execute in encryption mode, set the mode -e, and provide
 * the paths of receiver public key, sender private key, input
 * file and output cipher file
 * To execute in decryption mode, set the mode -d, and provide
 * the paths of receiver private key, sender public key, input
 * cipher file and output file
 * The program checks arguments first and then run the encrypt
 * or decrypt process
 */

import org.crypt.*;
import java.security.*;
import java.io.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

public class fcrypt {

	// function to check arguments
	public static void args_check(String[] args){
		if (args.length != 5){
			System.err.println("Incorrect arguments, please check README for usage info!");
			System.exit(-1);
		}
		String mod = args[0];
		if (mod.equals("-e") || mod.equals("-d")){
			return;
		}
		else{
			System.err.println("Incorrect mode!");
			System.exit(-1);
		}
	}
	public static void main(String[] args) throws Exception{
		args_check(args);
		if (args[0].equals("-e")){
			Encrypt enc = new Encrypt(args[1], args[2], args[3]);
			enc.encrypt_file(args[4]);
			enc.closeAll();
		}
		else{
			Decrypt dec = new Decrypt(args[2],args[1], args[3]);
			dec.decrypt_file(args[4]);
			dec.closeAll();
		}
	}	

}
