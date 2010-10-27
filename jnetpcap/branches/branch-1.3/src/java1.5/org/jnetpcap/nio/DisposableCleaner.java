/**
 * 
 */
package org.jnetpcap.nio;

import sun.misc.Cleaner;

/**
 * @author markbe
 * 
 */
public abstract class DisposableCleaner implements Disposable, Runnable {
	
	private final Cleaner cleaner;
	private boolean remove = false;

	public DisposableCleaner(Object referent) {
		cleaner = Cleaner.create(referent, this);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Runnable#run()
	 */
	public void run() {
		if (!remove) {
			dispose();		
		}
	}
	
	public void remove() {
		remove = true;
		cleaner.clean();
	}
}
