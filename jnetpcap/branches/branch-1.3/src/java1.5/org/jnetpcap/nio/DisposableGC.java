/**
 * 
 */
package org.jnetpcap.nio;

import java.lang.Thread.UncaughtExceptionHandler;
import java.lang.ref.ReferenceQueue;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
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
	private Semaphore memorySemaphore = new Semaphore(
			DisposableGC.MIN_MEMORY_RELEASE);
	private AtomicLong cleanupTimeout = new AtomicLong(
			DisposableGC.DEFAULT_CLEANUP_THREAD_TIMEOUT);
	private AtomicBoolean cleanupThreadProcessing = new AtomicBoolean(false);
	private static final long DEFAULT_CLEANUP_THREAD_TIMEOUT = 20;
	static final private int MANUAL_DRAING_MAX = 2;

	/**
	 * When maxDirectMemorySize is breached, this is the minimum amount of memory
	 * to release, triggering a System.gc() if necessary.
	 */
	private static final int MIN_MEMORY_RELEASE = 2 * 1024 * 1024;
	private static final long OUT_OF_MEMORY_TIMEOUT = 5 * 1000;
	private static final long G60 = 60 * 1000;
	private static final long G10 = 10 * 1000;

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

	final LinkSequence<DisposableReference> g0 =
			new LinkSequence<DisposableReference>("g0");
	final LinkSequence<DisposableReference> g10 =
			new LinkSequence<DisposableReference>("g10");
	final LinkSequence<DisposableReference> g60 =
			new LinkSequence<DisposableReference>("g60");

	private boolean verbose = false;
	/**
	 * A bit more verbose
	 */
	private boolean vverbose = false;

	final ReferenceQueue<Object> refQueue = new ReferenceQueue<Object>();

	/*
	 * private static class Marker extends PhantomReference<Object> {
	 * 
	 * @SuppressWarnings("unused") public final long id;
	 *//**
	 * @param id
	 *          unique marker id
	 */
	/*
	 * public Marker(long id) { super(new Object() { },
	 * DisposableGC.getDeault().markerQueue);
	 * 
	 * this.id = id; }
	 * 
	 * }
	 */
	final ReferenceQueue<Object> markerQueue = new ReferenceQueue<Object>();

	private static DisposableGC defaultGC = new DisposableGC();

	private long totalDisposed = 1;
	private boolean vvverbose;

	public static DisposableGC getDeault() {
		return defaultGC;
	}

	private DisposableGC() {
		startCleanupThread();
	}

	/*
	 * private long systemMinorGC() {
	 * 
	 * final long timestamp = System.currentTimeMillis(); Marker marker = new
	 * Marker(timestamp); // Now we wait for Marker to be
	 * 
	 * filler = 1;
	 * 
	 * while (true) { final Marker mark = (Marker) markerQueue.poll();
	 * 
	 * if (mark == marker) { while (markerQueue.poll() != null) { ; // Drain the
	 * queue quickly } break; } else {
	 * 
	 * filler++; new Object() { };
	 * 
	 * // Thread.yield(); try { if (filler % 10000 == 0) { Thread.sleep(1); } }
	 * catch (InterruptedException e) { } } }
	 * 
	 * return filler;
	 * 
	 * }
	 */
	public synchronized void invokeSystemGCAndWait() {

		long ts = System.currentTimeMillis();
		long low = JMemory.availableDirectMemorySize();

		try {
			if (isCleanupThreadActive()) {
				memorySemaphore.acquire(memorySemaphore.availablePermits());
				memorySemaphore.tryAcquire(MIN_MEMORY_RELEASE,
						OUT_OF_MEMORY_TIMEOUT,
						TimeUnit.MILLISECONDS);
			} else {
				System.gc();
				drainRefQueue(OUT_OF_MEMORY_TIMEOUT);
			}
		} catch (IllegalArgumentException e) {
		} catch (InterruptedException e) {
		}

		if (vverbose) {
			System.out.printf("DisposableGC: waiting for System.gc to finish:"
					+ " %dms, freed=%dMbytes%n",
					(System.currentTimeMillis() - ts),
					(JMemory.availableDirectMemorySize() - low) / (1024 * 1024));
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

	public void drainRefQueue(long timeout) throws IllegalArgumentException,
			InterruptedException {

		memorySemaphore.acquire(memorySemaphore.availablePermits()); // Grab all
		// of
		// them
		while (memorySemaphore.availablePermits() < MIN_MEMORY_RELEASE) {
			DisposableReference ref = (DisposableReference) refQueue.remove(timeout);
			if (ref == null) {
				break;
			}

			dispose(ref);
		}
	}

	void drainRefQueueLoop() throws InterruptedException {

		int count = 0;
		final long timeout = cleanupTimeout.get();
		long ts = System.currentTimeMillis();
		while (true) {

			final DisposableReference ref =
					(DisposableReference) refQueue.remove(timeout);

			if (ref != null) { // We have a reference to dispose of
				if (count == 0) { // First one
					if (vvverbose && cleanupThreadProcessing.get() == false) {
						System.out.printf("DisposableGC: working%n");
					}
					cleanupThreadProcessing.set(true);
					synchronized (cleanupThreadProcessing) {
						cleanupThreadProcessing.notifyAll(); // Signal start
					}
				}
				count++;

				/**
				 * Keep message coming even if we are continuously processing.
				 */
				if (vverbose && (count % 10000) == 0) {
					System.out
							.printf("DisposableGC: disposed of %4d entries " +
									"[total=%4dk/%4d(%2dMb),%4d(%2dMb),%4d(%2dMb)/%3dMb]%n",
									count,
									totalDisposed / 1000,
									g0.size(),
									mem(g0) / (1024 * 1024),
									g10.size(),
									mem(g10) / (1024 * 1024),
									g60.size(),
									mem(g60) / (1024 * 1024),
									memoryHeldInRefCollection() / (1024 * 1024));
				}

				/*
				 * Means, we just finished processing
				 */
			} else if (count != 0 && (System.currentTimeMillis() - ts) >= 1000) {
				ts = System.currentTimeMillis();
				sortGenerations();
				if (verbose && count > 00) {
					System.out
					.printf("DisposableGC: disposed of %4d entries " +
							"[total=%4dk/%4d(%2dMb),%4d(%2dMb),%4d(%2dMb)/%3dMb]%n",
									count,
									totalDisposed / 1000,
									g0.size(),
									mem(g0) / (1024 * 1024),
									g10.size(),
									mem(g10) / (1024 * 1024),
									g60.size(),
									mem(g60) / (1024 * 1024),
									memoryHeldInRefCollection() / (1024 * 1024));
				}

				count = 0;
				cleanupThreadProcessing.set(false);

				synchronized (cleanupThreadProcessing) { // Signal finish
					cleanupThreadProcessing.notifyAll();
				}
				if (vvverbose) {
					System.out
							.printf("DisposableGC: idle - waiting for system GC to collect more objects%n");
				}
			}

			if (ref == null) {
				if (cleanupThreadActive.get()) {
					if (memorySemaphore.hasQueuedThreads()) {
						System.gc();
					}

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

	/**
	 * 
	 */
	private void sortGenerations() {
		final long ct = System.currentTimeMillis();

		/*
		 * Check for G60(64 second) old generation
		 */
		for (DisposableReference ref : this.g10) {
			if ((ct - ref.getTs()) > G60) {
				g10.remove(ref);
				g60.add(ref);
			} else {
				break;
			}
		}

		/*
		 * Check for G10 (10 second) old generation
		 */
		for (DisposableReference ref : this.g0) {
			if ((ct - ref.getTs()) > G10) {
				g0.remove(ref);
				g10.add(ref);

				// System.out.printf("DisposableGC:: %s%n", ref);
			} else {
				break;
			}
			// System.out.printf("DisposableGC:: delta=%d%n", (ct - ref.getTs()));
		}
	}

	private long memoryHeldInRefCollection() {
		long size = 0;

		size += mem(g0);
		size += mem(g10);
		size += mem(g60);

		return size;
	}

	private static long mem(LinkSequence<DisposableReference> c) {
		long size = 0;
		for (DisposableReference ref : c) {
			size += ref.size();
		}

		return size;
	}

	private void dispose(DisposableReference ref) {

		synchronized (g0) {
			totalDisposed++;
			ref.dispose();
			ref.remove();

			// System.out.printf("DisposableGC: permits=%d released=1, mem=%d%n",
			// memorySemaphore.availablePermits(),
			// JMemory.availableDirectMemorySize());

			memorySemaphore.release(ref.size());

			if (g0.isEmpty() && g10.isEmpty() && g60.isEmpty()) {
				g0.notifyAll();
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

		synchronized (g0) {
			while (g0.isEmpty() == false) {
				if (isCleanupThreadActive()) {
					g0.wait();
				} else {
					drainRefQueue();
				}
			}
		}
	}

	public boolean waitForFullCleanup(long timeout) throws InterruptedException {

		synchronized (g0) {
			if (g0.isEmpty() == false) {
				if (isCleanupThreadActive()) {
					g0.wait(timeout);
				} else {
					drainRefQueue();
					if (g0.isEmpty() == false) {
						Thread.sleep(timeout);
						drainRefQueue();
					}
				}
			}

			return g0.isEmpty();
		}
	}

	public boolean isCleanupComplete() {
		synchronized (g0) {
			return g0.isEmpty();
		}
	}

	public void waitForForcableCleanup() throws InterruptedException {
		System.gc();
		while (waitForFullCleanup(5 * 1000) == false) {
			if (verbose && !cleanupThreadProcessing.get()) {
				System.out.printf("DisposableGC: waiting on %d elements%n", g0.size());
				for (int i = 0; i < g0.size(); i++) {
					DisposableReference o = g0.get(i);
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
