package cs6740.msg.loginAuth;
import cs6740.msg.Message;

/**
 * Class of 1st message of login anthentication 
 * @author Guanyu Wang, Xiaoyuan Liu
 *
 */
public class LoginRequest extends Message{

	/**
	 * 
	 */
	private static final long serialVersionUID = 8422817154454516469L;
	private final String content = "LOGIN REQUEST";
	public String getContent() {
		return content;
	}
	
}
