package cs6740.server;

import java.util.concurrent.ThreadPoolExecutor;

public class RejectHandler extends ThreadPoolExecutor.DiscardPolicy{
	public void rejectedExecution(ServerThread t, ThreadPoolExecutor executor) {
	}
}
