/**
 * 
 */
package org.jnetpcap.nio;

import java.lang.Thread.UncaughtExceptionHandler;
import java.lang.ref.ReferenceQueue;
import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;


/**
 * Specialized garbage-collector that invokes the
 * {@link DisposableReference.dispose} method immediately as soon as a
 * DisposableReference becomes unreferancable and put on the main garbage
 * collector's list.
 * 
 * @author markbe
 */
public final class DisposableGC {
	private Thread cleanupThread;
	private AtomicBoolean cleanupThreadActive = new AtomicBoolean(false);
	private AtomicLong cleanupTimeout =
			new AtomicLong(DisposableGC.DEFAULT_CLEANUP_THREAD_TIMEOUT);
	private AtomicBoolean cleanupThreadProcessing = new AtomicBoolean(false);
	private static final long DEFAULT_CLEANUP_THREAD_TIMEOUT = 500;
	static final private int MANUAL_DRAING_MAX = 2;

	/**
	 * Performance in 1000s of pps using various collection types:
	 * 
	 * <pre>
	 * Type           Threaded   Non-Threaded
	 *                 min-max     min-max
	 * ------------------------------------------------    
	 * ArrayDeque:    43.3-44.8   42.5-44.7
	 * ArrayList:     43.2-44.7   42.9-45.0
	 * LinkedList:    43.7-44.8   42.6-44.5
	 * HashSet:       43.3-44.4   41.2-43.5
	 * LinkedHashSet: 42.4-43.5   43.2-44.3
	 * </pre>
	 */
	final Collection<DisposableReference> refCollection3 =
	// new ArrayDeque<DisposableReference>(20000);
			new ArrayList<DisposableReference>(20000);
	// new LinkedList<DisposableReference>();
	// new HashSet<DisposableReference>(20000);
	// new LinkedHashSet<DisposableReference>(20000);

	final LinkSequence<DisposableReference> refCollection =
			new LinkSequence<DisposableReference>();

	private boolean verbose = false;
	/**
	 * A bit more verbose
	 */
	private boolean vverbose = false;

	final ReferenceQueue<Object> refQueue = new ReferenceQueue<Object>();

	private static DisposableGC defaultGC = new DisposableGC();

	private long totalDisposed = 1;

	public static DisposableGC getDeault() {
		return defaultGC;
	}

	private DisposableGC() {
//		startCleanupThread();
	}

	void drainRefQueueBounded() {
		int iterations = 0;
		while (iterations < MANUAL_DRAING_MAX) {
			DisposableReference ref = (DisposableReference) refQueue.poll();
			if (ref == null) {
				break;
			}

			dispose(ref);
			++iterations;
		}
	}

	public void drainRefQueue() {
		while (true) {
			DisposableReference ref = (DisposableReference) refQueue.poll();
			if (ref == null) {
				break;
			}

			dispose(ref);
		}
	}

	void drainRefQueueLoop() throws InterruptedException {

		int count = 0;
		final long timeout = cleanupTimeout.get();
		while (true) {

			final DisposableReference ref =
					(DisposableReference) refQueue.remove(timeout);

			if (ref != null) { // We have a reference to dispose of
				if (count == 0) { // First one
					cleanupThreadProcessing.set(true);
				}

				count++;

				/**
				 * Keep message coming even if we are continuesly processing.
				 */
				if (vverbose && (count % 1000000) == 0) {
					System.out
							.printf("DisposableGC:: disposed of %d entries [total=%dM]%n",
									count,
									totalDisposed / 1000000);
					count = 0;
				}
			} else if (count != 0) { // Means, we just finished processing
				if (verbose) {
					System.out
							.printf("DisposableGC:: disposed of %d entries [total=%dM]%n",
									count,
									totalDisposed / 1000000);
				}

				count = 0;
				cleanupThreadProcessing.set(false);
			}

			if (ref == null) {
				if (cleanupThreadActive.get()) {
					continue; // Null due to timeout
				} else {
					break;
				}
			}

			dispose(ref);
		}

		if (verbose && count != 0) {
			System.out.printf("DisposableGC:: disposed of %d entries [total=%dM]%n",
					count,
					totalDisposed / 1000000);
			count = 0;
		}
	}

	private void dispose(DisposableReference ref) {

		synchronized (refCollection) {
			totalDisposed++;
			ref.dispose();
			refCollection.remove(ref);

			if (refCollection.isEmpty()) {
				refCollection.notifyAll();
			}
		}

	}

	public long getCleanupThreadTimeout() {
		return cleanupTimeout.get();
	}

	public boolean isCleanupThreadActive() {
		return cleanupThreadActive.get() && cleanupThread.isAlive();
	}

	public void setCleanupThreadTimeout(long timeout) {
		cleanupTimeout.set(timeout);
	}

	public synchronized void startCleanupThread() {
		if (isCleanupThreadActive()) {
			return;
		}

		cleanupThread = new Thread(new Runnable() {

			@Override
			public void run() {
				try {
					drainRefQueueLoop();

				} catch (InterruptedException e) {
					UncaughtExceptionHandler handler;
					handler = Thread.getDefaultUncaughtExceptionHandler();
					handler.uncaughtException(Thread.currentThread(), e);

				} finally {
					cleanupThreadActive.set(false);
					cleanupThread = null;

					synchronized (this) {
						notifyAll();
					}
				}
			}

		}, "DisposableGC");

		cleanupThreadActive.set(true);

		cleanupThread.setDaemon(true);
		cleanupThread.setPriority(cleanupThread.getPriority() - 1); // Lower
		// priority
		cleanupThread.start();
	}

	public void stopCleanupThread() throws InterruptedException {
		if (isCleanupThreadActive()) {
			synchronized (cleanupThread) {
				cleanupThreadActive.set(false);

				if (cleanupThread != null) {
					cleanupThread.wait();
				}
			}
		}
	}

	public void waitForFullCleanup() throws InterruptedException {

		synchronized (refCollection) {
			while (refCollection.isEmpty() == false) {
				if (isCleanupThreadActive()) {
					refCollection.wait();
				} else {
					drainRefQueue();
				}
			}
		}
	}

	public boolean waitForFullCleanup(long timeout) throws InterruptedException {

		synchronized (refCollection) {
			if (refCollection.isEmpty() == false) {
				if (isCleanupThreadActive()) {
					refCollection.wait(timeout);
				} else {
					drainRefQueue();
					if (refCollection.isEmpty() == false) {
						Thread.sleep(timeout);
						drainRefQueue();
					}
				}
			}

			return refCollection.isEmpty();
		}
	}

	public boolean isCleanupComplete() {
		synchronized (refCollection) {
			return refCollection.isEmpty();
		}
	}

	public void waitForForcableCleanup() throws InterruptedException {
		System.gc();
		while (waitForFullCleanup(5 * 1000) == false) {
			if (verbose && !cleanupThreadProcessing.get()) {
				System.out.printf("DisposableGC:: waiting on %d elements%n",
						refCollection.size());
				for (int i = 0; i < refCollection.size(); i++) {
					DisposableReference o = refCollection.get(i);
					if (o != null && o.get() != null) {
						System.out.printf("DisposableGC::#%d: %s%n", i, o.get());
					} else {
						System.out.printf("DisposableGC::#%d: %s%n", i, null);
					}
				}
			}
		}

	}

	public boolean waitForForcableCleanup(long timeout)
			throws InterruptedException {
		int count = (int) (timeout / 100) + 1;
		while ((count-- >= 0) && waitForFullCleanup(100) == false) {
			System.gc();
		}

		return isCleanupComplete();
	}

	/**
	 * @return the verbose
	 */
	public boolean isVerbose() {
		return verbose;
	}

	/**
	 * @param verbose
	 *          the verbose to set
	 */
	public void setVerbose(boolean verbose) {
		this.verbose = verbose;

		if (!verbose) {
			setVVerbose(false);
		}

	}

	/**
	 * @return the vverbose
	 */
	public boolean isVVerbose() {
		return vverbose;
	}

	/**
	 * @param vverbose
	 *          the vverbose to set
	 */
	public void setVVerbose(boolean vverbose) {
		if (vverbose) {
			setVerbose(true);
		}
		this.vverbose = vverbose;
	}
}
