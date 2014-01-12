package cs6740.client;

import java.util.concurrent.ThreadPoolExecutor;

/*
 * Handler of threads being rejected by thread pool
 */
public class RejectHandler extends ThreadPoolExecutor.DiscardPolicy{
	public void rejectedExecution(ClientAuthThread t, ThreadPoolExecutor executor) {
	}
}
