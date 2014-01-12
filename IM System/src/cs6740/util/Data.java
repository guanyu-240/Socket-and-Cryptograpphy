package cs6740.util;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Date;

/*
 * Class of operating different kinds of data
 */
public class Data {
	
	/*
	 * generate random number
	 */
	public static int randomNumber(int numBits){
		SecureRandom gen = new SecureRandom(long2Bytes(timestamp()));
		int rand = Math.abs(gen.nextInt());
		return (int) (rand % Math.pow(2, numBits));
	}
	
	/*
	 * generate random BigInteger
	 */
	public static BigInteger randomBigInteger(int numBits){
		SecureRandom gen = new SecureRandom(long2Bytes(timestamp()));
		BigInteger bi = BigInteger.probablePrime(numBits, gen);
		return bi;
	}
	
	/*
	 * get timestamp in long
	 */
	public static long timestamp(){
		return (new Date()).getTime();
	}
	
	/*
	 * convert int to byte array
	 */
	public static byte[] int2Bytes(int number){
		ByteBuffer buf = ByteBuffer.allocate(4);
		buf.putInt(number);
		return buf.array();
	}
	
	/*
	 * convert byte array to int
	 */
	public static int bytesToInt(byte[] arr){
		ByteBuffer buf = ByteBuffer.wrap(arr);
		return buf.getInt();
	}
	
	/*
	 * convert long to byte array
	 */
	public static byte[] long2Bytes(long number){
		ByteBuffer buf = ByteBuffer.allocate(8);
		buf.putLong(number);
		return buf.array();
	}
	
	/*
	 * convert byte array to long
	 */
	public static long bytesToLong(byte[] arr){
		ByteBuffer buf = ByteBuffer.wrap(arr);
		return buf.getLong();
	}
	
	/*
	 * merge two byte arrays
	 */
    public static byte[] mergeBytes(byte[] byte1, byte[] byte2){  
        byte[] byte3 = new byte[byte1.length+byte2.length];  
        System.arraycopy(byte1, 0, byte3, 0, byte1.length);  
        System.arraycopy(byte2, 0, byte3, byte1.length, byte2.length);  
        return byte3;  
    }  
    
    /*
     * get sub byte array of a byte array
     */
    public static byte[] subBytes(byte[] data, int start, int length){
    	byte[] ret = new byte[length];
    	System.arraycopy(data, start, ret, 0, length);
    	return ret;
    }
	
			
	public static int genPrime(int bitLength){
		bitLength = Math.min(bitLength, 31);
		SecureRandom rand= new SecureRandom(long2Bytes(timestamp()));
		BigInteger bI = BigInteger.probablePrime(bitLength, rand);
		return bI.intValue();
	}
	
	public static int solveChallenge(int numBits, byte[] hashValue, byte[] salt){
		int ret = 0;
		numBits = Math.max(numBits, 12);
		int min = 0;
		int max = (int) Math.pow(2.0, (double)numBits);
		for (ret = min; ret < max; ret ++){
			byte[] chal = int2Bytes(ret);
			byte[] combine = mergeBytes(chal, salt);
			if (Arrays.equals(hashValue, Hash.hashMsg(combine, "SHA1"))){
				return ret;
			}
		}
		return -1;
	}
	
	public static void byteTohex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                            '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }
    public static String bytes2HexString(byte[] block) {
        StringBuffer buf = new StringBuffer();

        int len = block.length;

        for (int i = 0; i < len; i++) {
             byteTohex(block[i], buf);
        }
        return buf.toString();
    }
    
    public static byte[] hexStr2Bytes(String hex){
    	
    	return null;
    }
}
