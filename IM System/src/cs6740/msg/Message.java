package cs6740.msg;

import java.io.*;

/*
 *  Message Object
 *  
 *  Author: Guanyu Wang, Xiaoyuan Liu
 */

public class Message implements Serializable {
	/**
	 * 
	 */
	public static final int MAXLEN = 2048;
	private static final long serialVersionUID = -9135943338145335492L;
	private void readObject(ObjectInputStream mInputStream) throws IOException, ClassNotFoundException{
		mInputStream.defaultReadObject();
	}
	private void writeObject(ObjectOutputStream mOutputStream) throws IOException{
		mOutputStream.writeObject(this);
	}
	public void readMessage(ObjectInputStream mInputStream){
		try {
			readObject(mInputStream);
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
	}
	
	/*
	 *  write message into ObjectOutputStream
	 */
	public void writeMessage(ObjectOutputStream mOutputStream) throws IOException{
			writeObject(mOutputStream);
	}
	
	/**
	 * 
	 * @return the byte[] of serialized "this" object
	 */
	public byte[] object2Bytes(){
		ByteArrayOutputStream baos = new  ByteArrayOutputStream(); 
		try
		{
		    ObjectOutputStream out = new ObjectOutputStream(baos);
		    out.writeObject(this);
		    return baos.toByteArray();
		} catch (IOException e) 
		{    
		    e.printStackTrace();
		}
		return null;
	}
	/**
	 * 
	 * @param objBytes
	 * @return object from byte[]
	 */
	public static Object bytes2Object(byte[] objBytes){
		ByteArrayInputStream bin = new ByteArrayInputStream(objBytes);
		try 
		{
		    ObjectInputStream obin = new ObjectInputStream(bin);
		    Object obj = obin.readObject();
		    return obj;
		}
		catch(Exception e)
		{
		    e.printStackTrace();
		}
		return null;
	}
	
	public static Object readAnObject(ObjectInputStream objin) throws ClassNotFoundException, IOException{
		    Object obj = objin.readObject();
		    return obj;
	}
}
