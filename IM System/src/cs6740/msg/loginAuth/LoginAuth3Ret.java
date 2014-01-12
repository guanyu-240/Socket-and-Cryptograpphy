package cs6740.msg.loginAuth;

import cs6740.msg.loginAuth.LoginAuth3.LoginAuth3Plain;

public class LoginAuth3Ret {
	public static final int CORRECT = 0;
	public static final int WRONG = -1;
	public static final int BLOCKED = -2;
	public static final int ALREADY_LOGGED_IN = -3;
	private LoginAuth3Plain login3;
	private int result;
	public LoginAuth3Ret(LoginAuth3Plain login3){
		this.login3 = login3;
		this.setResult(CORRECT);
	}
	public LoginAuth3Plain getLogin3() {
		return login3;
	}
	public void setLogin3(LoginAuth3Plain login3) {
		this.login3 = login3;
	}
	public int getResult() {
		return result;
	}
	public void setResult(int result) {
		this.result = result;
	}

}
