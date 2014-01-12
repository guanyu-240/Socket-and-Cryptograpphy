package cs6740.msg.loginAuth;

import cs6740.util.DHExchange;

public class LoginAuth4Ret {
	public static final int CORRECT = 0;
	public static final int WRONG = -1;
	public static final int BLOCKED = -2;
	public static final int ALREADY_LOGGED_IN = -3;
	private DHExchange dh;
	private int r3;
	private int result;
	public DHExchange getDh() {
		return dh;
	}
	public void setDh(DHExchange dh) {
		this.dh = dh;
	}
	public int getR3() {
		return r3;
	}
	public void setR3(int r3) {
		this.r3 = r3;
	}
	public int getResult() {
		return result;
	}
	public void setResult(int result) {
		this.result = result;
	}

}
