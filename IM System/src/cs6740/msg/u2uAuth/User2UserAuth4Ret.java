package cs6740.msg.u2uAuth;

public class User2UserAuth4Ret {
	private int r2;
	private byte[] dhPub;
	public int getR2() {
		return r2;
	}
	public void setR2(int r2) {
		this.r2 = r2;
	}
	public byte[] getDhPub() {
		return dhPub;
	}
	public void setDhPub(byte[] dhPub) {
		this.dhPub = dhPub;
	}
	public User2UserAuth4Ret(int r2, byte[] dhPub){
		this.setR2(r2);
		this.setDhPub(dhPub);
	}
}
