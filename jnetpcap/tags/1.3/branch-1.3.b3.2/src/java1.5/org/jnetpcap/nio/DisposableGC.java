/**
 * 
 */
package org.jnetpcap.nio;

import java.lang.Thread.UncaughtExceptionHandler;
import java.lang.ref.Reference;
import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
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
	private static final long DEFAULT_CLEANUP_THREAD_TIMEOUT = 10;
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
	// final Collection<DisposableReference> refCollection3 =
	// new ArrayDeque<DisposableReference>(20000);
	// new ArrayList<DisposableReference>(20000);
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

/*	private static class Marker extends PhantomReference<Object> {

		@SuppressWarnings("unused")
		public final long id;

		*//**
		 * @param id
		 *          unique marker id
		 *//*
		public Marker(long id) {
			super(new Object() {
			}, DisposableGC.getDeault().markerQueue);

			this.id = id;
		}

	}
*/
	final ReferenceQueue<Object> markerQueue = new ReferenceQueue<Object>();

	private static DisposableGC defaultGC = new DisposableGC();

	private long totalDisposed = 1;
	private long filler;
	private boolean vvverbose;

	public static DisposableGC getDeault() {
		return defaultGC;
	}

	private DisposableGC() {
		// startCleanupThread();
	}

/*	private long systemMinorGC() {

		final long timestamp = System.currentTimeMillis();
		Marker marker = new Marker(timestamp); // Now we wait for Marker to be

		filler = 1;

		while (true) {
			final Marker mark = (Marker) markerQueue.poll();

			if (mark == marker) {
				while (markerQueue.poll() != null) {
					; // Drain the queue quickly
				}
				break;
			} else {

				filler++;
				new Object() {
				};

				// Thread.yield();
				try {
					if (filler % 10000 == 0) {
						Thread.sleep(1);
					}
				} catch (InterruptedException e) {
				}
			}
		}

		return filler;

	}
*/
	public void invokeSystemGCAndWait() {
		long ts = System.currentTimeMillis();
		@SuppressWarnings("unused")
		final Reference<Object> marker = new WeakReference<Object>(new Object() {
		}, markerQueue);
		System.gc();
		try {
			markerQueue.remove(200); // Wait upto 200ms, for our marker
			Thread.sleep(10); // Fiddle time
			long te = System.currentTimeMillis();
			if (vverbose) {
				System.out
						.printf("DisposableGC: waiting for System.gc to finish: %dms%n",
								(te - ts));
			}
		} catch (InterruptedException e) {
		}

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
		int collectionSize = 0;
		while (true) {

			final DisposableReference ref =
					(DisposableReference) refQueue.remove(timeout);

			if (ref != null) { // We have a reference to dispose of
				if (count == 0) { // First one
					if (vvverbose && cleanupThreadProcessing.get() == false) {
						System.out.printf("DisposableGC: working%n");
					}
					cleanupThreadProcessing.set(true);

					collectionSize = refCollection.size();
					collectionSize = (collectionSize < 1000) ? 1000 : collectionSize;
				}
				count++;

				/**
				 * Keep message coming even if we are continuesly processing.
				 */
				if (vverbose && (count % 10000) == 0) {
					System.out
							.printf("DisposableGC: disposed of %d entries [total=%dk/%d]%n",
									count,
									totalDisposed / 1000,
									filler);
					count = 0;
				}
			} else if (count != 0) { // Means, we just finished processing
				if (verbose && count > 400) {
					System.out
							.printf("DisposableGC: disposed of %d entries [total=%dK/%d]%n",
									count,
									totalDisposed / 1000,
									filler);
				}

				count = 0;
				cleanupThreadProcessing.set(false);
				if (vvverbose) {
					System.out
							.printf("DisposableGC: idle - waiting for system GC to collect more objects%n");
				}
			}

			if (ref == null) {
				if (cleanupThreadActive.get()) {
					continue; // Null due to timeout
				} else {
					if (verbose) {
						System.out.printf("DisposableGC: finished%n");
					}
					break;
				}
			}

			dispose(ref);
		}

		if (verbose && count != 0) {
			System.out.printf("DisposableGC: disposed of %d entries [total=%dM]%n",
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
				System.out.printf("DisposableGC: waiting on %d elements%n",
						refCollection.size());
				for (int i = 0; i < refCollection.size(); i++) {
					DisposableReference o = refCollection.get(i);
					if (o != null && o.get() != null) {
						System.out.printf("DisposableGC:#%d: %s%n", i, o.get());
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
			setVVVerbose(false);
		}

	}

	/**
	 * @return the vverbose
	 */
	public boolean isVVerbose() {
		return vverbose;
	}

	/**
	 * @return the vvverbose
	 */
	public boolean isVVVerbose() {
		return vvverbose;
	}

	/**
	 * @param vverbose
	 *          the vverbose to set
	 */
	public void setVVerbose(boolean vverbose) {
		if (vverbose) {
			setVerbose(true);
		} else {
			setVVVerbose(false);
		}
		
		this.vverbose = vverbose;
	}

	/**
	 * @param vvverbose
	 *          the vvverbose to set
	 */
	public void setVVVerbose(boolean vvverbose) {
		if (vvverbose) {
			setVVerbose(true);
		}
		this.vvverbose = vvverbose;
	}
}
