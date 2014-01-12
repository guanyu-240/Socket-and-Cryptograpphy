package cs6740.client;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
/*
 * ClientThreadPool, for managing client threads of listening authentications
 */
public class ClientThreadPool extends ThreadPoolExecutor{
	public ClientThreadPool(int corePoolSize, int maximumPoolSize,
			long keepAliveTime, TimeUnit unit, BlockingQueue<Runnable> workQueue) {
		super(corePoolSize, maximumPoolSize, keepAliveTime, unit, workQueue);
	}
	
}
