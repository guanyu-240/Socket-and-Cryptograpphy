package cs6740.user;

import java.net.InetAddress;

public class UserMappingKey{
	private InetAddress addr;
	private int udpPort;
	public InetAddress getAddr() {
		return addr;
	}
	public void setAddr(InetAddress addr) {
		this.addr = addr;
	}
	public UserMappingKey(InetAddress addr, int udpPort){
		this.addr = addr;
		this.udpPort = udpPort;
	}
	
	public int getUdpPort() {
		return udpPort;
	}
	public void setUdpPort(int udpPort) {
		this.udpPort = udpPort;
	}
}
