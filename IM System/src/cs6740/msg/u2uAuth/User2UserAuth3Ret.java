package cs6740.msg.u2uAuth;


import cs6740.msg.u2uAuth.User2UserAuth3.U2UAuth3Plain;
import cs6740.util.AESCrypt;

public class User2UserAuth3Ret {
	private U2UAuth3Plain auth3;
	private AESCrypt aesTmp;
	public User2UserAuth3Ret(U2UAuth3Plain auth3, AESCrypt aesTmp){
		this.auth3 = auth3;
		this.aesTmp = aesTmp;
	}
	public U2UAuth3Plain getAuth3() {
		return auth3;
	}
	public void setAuth3(U2UAuth3Plain auth3) {
		this.auth3 = auth3;
	}
	public AESCrypt getAesTmp() {
		return aesTmp;
	}
	public void setAesTmp(AESCrypt aesTmp) {
		this.aesTmp = aesTmp;
	} 
}
