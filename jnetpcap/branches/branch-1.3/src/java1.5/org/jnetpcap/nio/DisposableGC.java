/**
 * 
 */
package org.jnetpcap.nio;

import java.lang.Thread.UncaughtExceptionHandler;
import java.lang.ref.Reference;
import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.sql.Time;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import org.jnetpcap.util.Units;

/**
 * Specialized garbage-collector that invokes the
 * {@link DisposableReference.dispose} method immediately as soon as a
 * DisposableReference becomes unreferancable and put on the main garbage
 * collector's list.
 * 
 * @author markbe
 */
public final class DisposableGC {
	private static final long DEFAULT_CLEANUP_THREAD_TIMEOUT = 20;
	private static DisposableGC defaultGC = new DisposableGC();
	private static final long G10 = 10 * 1000;
	private static final long G60 = 60 * 1000;

	static final private int MANUAL_DRAING_MAX = 2;

	/**
	 * When maxDirectMemorySize is breached, this is the minimum amount of memory
	 * to release, triggering a System.gc() if necessary.
	 */
	static final int MIN_MEMORY_RELEASE = 2 * Units.MEBIBYTE;

	/**
	 * Minimum delay before 2 consecutive System.gc calls can be made
	 */
	static final long MIN_SYSTEM_GC_INVOKE_TIMEOUT = 200;

	static final long OUT_OF_MEMORY_TIMEOUT = 15 * 1000;

	public static DisposableGC getDeault() {
		return defaultGC;
	}

	private static long mem(LinkSequence<DisposableReference> c) {
		long size = 0;
		for (DisposableReference ref : c) {
			size += ref.size();
		}

		return size;
	}

	private Thread cleanupThread;
	private AtomicBoolean cleanupThreadActive = new AtomicBoolean(false);

	private AtomicBoolean cleanupThreadProcessing = new AtomicBoolean(false);

	private AtomicLong cleanupTimeout = new AtomicLong(
			DisposableGC.DEFAULT_CLEANUP_THREAD_TIMEOUT);

	private long deltaCount;

	private long deltaSize;
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
	private long lastSystemGCInvoke = 0;
	private long firstSystemGCNeeded = 0;

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

	private Reference<Object> markerReference;

	private Semaphore memorySemaphore = new Semaphore(
			DisposableGC.MIN_MEMORY_RELEASE);

	final ReferenceQueue<Object> refQueue = new ReferenceQueue<Object>();

	private long totalDisposed = 1;

	private long totalSize;

	private boolean verbose = false;

	/**
	 * A bit more verbose
	 */
	private boolean vverbose = false;

	private boolean vvverbose = false;

	private DisposableGC() {
		startCleanupThread();

		try {
		verbose = Boolean.parseBoolean(System.getProperty("nio.verbose", "false"));
		vverbose =
				Boolean.parseBoolean(System.getProperty("nio.vverbose", "false"));
		vvverbose =
				Boolean.parseBoolean(System.getProperty("nio.vvverbose", "false"));
		} catch (Exception e) {
			// Ignore any formatting exceptions from the command line
		}
	}

	private void dispose(DisposableReference ref) {

		synchronized (g0) {
			memorySemaphore.release(ref.size());

			totalDisposed++;
			totalSize += ref.size();
			ref.dispose();
			ref.remove();

			if (g0.isEmpty() && g10.isEmpty() && g60.isEmpty()) {
				g0.notifyAll();
			}
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

		/*
		 * Breakup the timeout into 100 partitions so that we can check the permits
		 * more often then just a single monolithic times.
		 */
		long partition = timeout / 100;
		while (memorySemaphore.availablePermits() < MIN_MEMORY_RELEASE) {
			DisposableReference ref = (DisposableReference) refQueue.remove(timeout);

			if (ref == null && partition++ < 100) {
				continue;
			}

			if (ref == null) {
				break;
			}

			dispose(ref);
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

	void drainRefQueueLoop() throws InterruptedException {

		deltaCount = 0;
		deltaSize = 0;
		final long timeout = cleanupTimeout.get();
		long ts = System.currentTimeMillis();
		while (true) {

			final DisposableReference ref =
					(DisposableReference) refQueue.remove(timeout);

			if (ref != null) { // We have a reference to dispose of
				if (deltaCount == 0) { // First one
					if (vvverbose && cleanupThreadProcessing.get() == false) {
						logBusy();
					}
					cleanupThreadProcessing.set(true);
					synchronized (cleanupThreadProcessing) {
						cleanupThreadProcessing.notifyAll(); // Signal start
					}
				}
				deltaCount++;
				deltaSize += ref.size();

				/**
				 * Keep message coming even if we are continuously processing.
				 */
				if (vverbose && (deltaCount % 10000) == 0) {
					sortGenerations();
					logUsage();
				}

				/*
				 * Means, we just finished processing
				 */
			} else if (deltaCount != 0 && (System.currentTimeMillis() - ts) >= 1000) {
				ts = System.currentTimeMillis();
				sortGenerations();
				if (verbose && deltaCount > 00) {
					logUsage();
				}

				deltaCount = 0;
				deltaSize = 0;
				cleanupThreadProcessing.set(false);

				synchronized (cleanupThreadProcessing) { // Signal finish
					cleanupThreadProcessing.notifyAll();
				}
				if (vvverbose) {
					logIdle();
				}
			}

			if (ref == null) {
				if (cleanupThreadActive.get()) {
					if (memorySemaphore.hasQueuedThreads()) {
						invokeSystemGC();
					}

					continue; // Null due to timeout
				} else {
					if (verbose) {
						logFinished();
					}
					break;
				}
			}

			dispose(ref);
		}

		if (verbose && deltaCount != 0) {
			System.out.printf("DisposableGC: disposed of %d entries [total=%dM]%n",
					deltaCount,
					totalDisposed / 1000000);
			deltaCount = 0;
		}
	}

	private String f(long l) {
		return f(l, -1, "");
	}

	@SuppressWarnings("unused")
	private String f(long l, int percision) {
		return f(l, percision, "");
	}

	private String f(long l, int percision, String post) {
		String u = "";
		double v = l;
		int p = 0;
		if (l > Units.TEBIBYTE) {
			u = "t";
			v /= 3;
			p = 4;
		} else if (l > Units.GIGIBYTE) {
			u = "g";
			v /= Units.GIGIBYTE;
			p = 2;
		} else if (l > Units.MEBIBYTE) {
			u = "m";
			v /= Units.MEBIBYTE;
			p = 1;
		} else if (l > Units.KIBIBYTE) {
			u = "k";
			v /= Units.KIBIBYTE;
			p = 0;
		} else {
			p = 0;
		}

		if (percision != -1) {
			p = percision;
		}

		String f = String.format("%%.%df%%s%%s", p);

		return String.format(f, v, u, post);
	}

	private String fb(long l) {
		return f(l, -1, "b");
	}

	private String fb(long l, int percision) {
		return f(l, percision, "b");
	}

	public long getCleanupThreadTimeout() {
		return cleanupTimeout.get();
	}

	/**
	 * Makes sure that JVM GC is not invoked more then a certain timeout value
	 * since the last time it was invoked. Avoids too many JVM GC invocation calls
	 * that might overlap
	 * 
	 * @return true if JVM GC was invoked, otherwise false
	 */
	private boolean invokeSystemGC() {

		if ((System.currentTimeMillis() - lastSystemGCInvoke) < MIN_SYSTEM_GC_INVOKE_TIMEOUT) {
			return false;
		}

		if (vverbose) {
			logSystemGC();
		}

		System.gc();
		lastSystemGCInvoke = System.currentTimeMillis();
		firstSystemGCNeeded = 0;

		return true;
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
		long low = JMemory.availableDirectMemory();

		try {
			if (isCleanupThreadActive()) {
				memorySemaphore.acquire(memorySemaphore.availablePermits());
				memorySemaphore.tryAcquire(MIN_MEMORY_RELEASE,
						OUT_OF_MEMORY_TIMEOUT,
						TimeUnit.MILLISECONDS);
			} else {
				invokeSystemGC();
				drainRefQueue(OUT_OF_MEMORY_TIMEOUT);
			}
		} catch (IllegalArgumentException e) {
		} catch (InterruptedException e) {
		}

		if (vverbose) {
			System.out.printf("DisposableGC: waiting for System.gc to finish:"
					+ " %dms, freed=%dMbytes%n",
					(System.currentTimeMillis() - ts),
					(JMemory.availableDirectMemory() - low) / (1024 * 1024));
		}
	}

	/**
	 * Issues a JVM GC request, while injecting a marker reference to be cleaned
	 * up by the very same JVM GC run. Until our marker reference is not cleaned
	 * up, we do not issue another JVM GC since this means that previous GC run
	 * has not reached our marker reference yet.
	 */
	public synchronized void invokeSystemGCWithMarker() {

		if (markerReference != null && markerReference.get() != null
				|| !isSystemGCReady()) {
			return;
		}

		if (vvverbose) {
			logMarker();
		}
		markerReference = new WeakReference<Object>(new Object() {
		});
		invokeSystemGC();
	}

	public boolean isCleanupComplete() {
		synchronized (g0) {
			return g0.isEmpty();
		}
	}

	public boolean isCleanupThreadActive() {
		return cleanupThreadActive.get() && cleanupThread.isAlive();
	}

	/**
	 * Checks if JVM GC can be called upon, at this particular time. If the
	 * previous invocation of JVM GC was less then minimum delay between
	 * consecutive calls, this function returns false.
	 * 
	 * @return true if JVM GC can be invoked at this time, otherwise false
	 */
	private final boolean isSystemGCReady() {
		if (firstSystemGCNeeded == 0) {
			firstSystemGCNeeded = System.currentTimeMillis();
		}

		return cleanupThreadProcessing.get() == false
				&& (System.currentTimeMillis() - lastSystemGCInvoke) > MIN_SYSTEM_GC_INVOKE_TIMEOUT;
	}

	/**
	 * @return the verbose
	 */
	public boolean isVerbose() {
		return verbose;
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

	private void logBusy() {
		System.out.printf("DisposableGC: busy%n");
	}

	private void logFinished() {
		System.out.printf("DisposableGC: finished%n");
	}

	private void logIdle() {
		System.out.printf("DisposableGC: idle - "
				+ "waiting for system GC to collect more objects%n");

	}

	/**
	 * 
	 */
	private void logLimits() {
		System.out
				.printf("DisposableGC: current native memory allocation limits are max=%s, soft=%s%n",
						fb(JMemory.maxDirectMemory()),
						fb(JMemory.softDirectMemory()));

	}

	/**
	 * 
	 */
	private void logMarker() {
		long ts = System.currentTimeMillis();
		long fs = ts - (ts / 1000) * 1000;

		/*
		 * Provide TS to fraction of a second in millis
		 */
		System.out.printf("DisposableGC: soft limit breached, "
				+ "issued a marker at %s.%d, minimum delay=%dms%n",
				new Time(ts),
				fs,
				MIN_SYSTEM_GC_INVOKE_TIMEOUT);

	}

	/**
	 * 
	 */
	private void logSystemGC() {
		long ts = System.currentTimeMillis();
		long fs = ts - (ts / 1000) * 1000;
		long waited = ts - firstSystemGCNeeded;

		System.out
				.printf("DisposableGC: issued JVM GC request %s.%d waited=%dms (reserved=%s, available=%s)%n",
						new Time(ts),
						fs,
						waited,
						fb(JMemory.reservedDirectMemory()),
						fb(JMemory.availableDirectMemory()));

	}

	private void logUsage() {
		System.out.printf("DisposableGC: [immediate=%3s(%4s)]=%3s(%7s) "
				+ "[0sec=%3s(%6s),10sec=%3s(%6s),60sec=%3s(%6s)]=%6s%n",
				f(deltaCount),
				fb(deltaSize, 0),
				f(totalDisposed),
				fb(totalSize),
				f(g0.size()),
				fb(mem(g0)),
				f(g10.size()),
				fb(mem(g10)),
				f(g60.size()),
				fb(mem(g60)),
				fb(memoryHeldInRefCollection()));

	}

	private long memoryHeldInRefCollection() {
		long size = 0;

		size += mem(g0);
		size += mem(g10);
		size += mem(g60);

		return size;
	}

	public void setCleanupThreadTimeout(long timeout) {
		cleanupTimeout.set(timeout);
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
		} else {
			logLimits();
		}

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
			invokeSystemGC();
		}

		return isCleanupComplete();
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
}
