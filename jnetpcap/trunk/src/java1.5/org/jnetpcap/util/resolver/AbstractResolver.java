package org.jnetpcap.util.resolver;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.URL;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.Queue;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jnetpcap.util.JEvent;
import org.jnetpcap.util.config.JConfig;

/**
 * Default adaptor class for Resovler interface. This abstract class provides
 * the default caching mechanism for positive and negative resolver lookups. It
 * also provides a timeout mechanism to time out lookup results.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class AbstractResolver implements Resolver,
    PropertyChangeListener {

	/**
	 * Internal class that keeps track of timeout and which key to time out. Key
	 * is hash of the address that was cached.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	private static class TimeoutEntry {
		public final long hash;

		public final long timeout;

		/**
		 * @param key
		 */
		public TimeoutEntry(long key, long timeout) {
			this.hash = key;
			this.timeout = System.currentTimeMillis() + timeout;

			if (this.timeout < 0 || (this.timeout - System.currentTimeMillis()) < 0) {
				throw new IllegalStateException("timeout overflow " + timeout);
			}
		}
	}

	private static final int DEFAULT_BACKOFF = 10;

	private static final String DEFAULT_CACHE_SUFFIX = ".resolver";

	private static final String DEFAULT_HOME = "@{user.home}/@{${subdir}}";

	private static final int DEFAULT_MAX_ENTRIES = 1000;

	private static final boolean DEFAULT_MKDIR_HOME = false;

	private static final long DEFAULT_NEGATIVE_TIMEOUT_IN_MILLIS = 30 * 60 * 1000;

	/**
	 * Timeout of 5 years
	 */
	protected static final long INFINITE_TIMEOUT =
	    1000L * 60L * 60L * 24L * 365L * 5L;

	private static final long DEFAULT_POSITIVE_TIMEOUT_IN_MILLIS =
	    24 * 60 * 60 * 1000;

	private static final boolean DEFAULT_SAVE_CACHE = false;

	private static final String NEWLINE_SEPARATOR =
	    System.getProperty("line.separator");

	private static final String PROPERTY_BACKOFF = "resolver.%sbackoff";

	private static final String PROPERTY_CACHE_SUFFIX = "resolver.suffix";

	private static final String PROPERTY_MAX_ENTRIES = "resolver.%smaxentries";

	private static final String PROPERTY_MKDIR_HOME = "resolver.home.mkdir";

	private static final String PROPERTY_NEGATIVE_TIMEOUT =
	    "resolver.%stimeout.negative";

	private static final String PROPERTY_POSITIVE_TIMEOUT =
	    "resolver.%stimeout.positive";

	private static final String PROPERTY_RESOLVER_HOME = "resolver.home";

	private static final String PROPERTY_RESOLVER_HOME_SEARCH_PATH =
	    "resolver.home.search.path";

	private static final String PROPERTY_RESOLVER_FILE_SEARCH_PATH =
	    "resolver.search.path";

	private static final String PROPERTY_SAVE_CACHE = "resolver.%ssave";

	/**
	 * Percentage of how many oldest entries to remove from cache
	 */
	private int backoff = DEFAULT_BACKOFF;

	/**
	 * Main cache map. The timeout is maintaned using a priority queue, that
	 * removes timedout entries from this map.
	 */
	private Map<Long, String> cache;

	/**
	 * Just an initial map size.
	 */
	private int cacheCapacity = 100;

	private float cacheLoadFactor = 0.75f;

	/**
	 * Flag used to mark if any changes have been made to the cache that need to
	 * be saved
	 */
	private boolean isModified = false;

	/**
	 * Logger is supplied from subclass. This allows Abstract logger to log
	 * messages attached to actual logger that was intended for
	 */
	protected final Logger logger;

	/**
	 * Hard limit on how many entries can be stored in a cache. When this limit is
	 * reached, backoff percentage is used to calculate the number of oldest
	 * entries to remove to make room for new entries.
	 */
	private int maxentries = DEFAULT_MAX_ENTRIES;

	/**
	 * If set to true, we are allowed to create our resolver home directory, which
	 * defaults to jnetpcap home directory.
	 */
	private boolean mkdirHome = DEFAULT_MKDIR_HOME;

	/**
	 * Name of this resolver. Same as enum constant name. Used in file names and
	 * resolver specific properties.
	 */
	private final String name;

	/**
	 * When failed to resolve to a name, store the failure information in cache
	 * and set the negative hit timeout.
	 */
	private long negativeTimeout = DEFAULT_NEGATIVE_TIMEOUT_IN_MILLIS;

	/**
	 * Resolved to a name.
	 */
	private long positiveTimeout = DEFAULT_POSITIVE_TIMEOUT_IN_MILLIS;

	private boolean saveCache = DEFAULT_SAVE_CACHE;

	private Queue<AbstractResolver.TimeoutEntry> timeoutQueue;

	public AbstractResolver(Logger logger, ResolverType type) {
		this(logger, type.name());
	}

	public AbstractResolver(Logger logger, String name) {
		this.logger = logger;
		this.name = name;
		if (name == null || name.length() == 0) {
			throw new IllegalArgumentException("resolver's name must be set");
		}
		// System.out.printf("%s: %s %s\n", name, logger, logger.getLevel());

	}

	public void addToCache(long hash, String name) {
		if (name != null && positiveTimeout != 0) {
			addToCache(hash, name, positiveTimeout);
		}

		if (name == null && negativeTimeout != 0) {
			addToCache(hash, name, negativeTimeout);
		}
	}

	public void addToCache(long hash, String name, long timeout) {

		if (cache.containsKey(hash)) {
			logger.finest(String.format("[%d] replacing %X", cache.size(), hash));
			cache.remove(hash);
		} else {
			if (logger.isLoggable(Level.FINEST)) {
				logger.finest(String.format("[%d] adding %X %s", cache.size(), hash,
				    String.valueOf(name)));
			}
		}

		isModified = true;
		cache.put(hash, name);

		TimeoutEntry e;
		timeoutQueue.add(e = new TimeoutEntry(hash, timeout));

		if (cache.size() >= maxentries) {
			timeoutCacheOldest(maxentries * 100 / backoff);
		}

		long d = e.timeout - System.currentTimeMillis();
		if (d != timeout) {
			logger.finest(String.format("invalid timeout %d != %d", d, timeout));
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see packet.format.JFormatter.Resolver#isResolved(byte[])
	 */
	public boolean canBeResolved(byte[] address) {
		return resolve(address) != null;
	}

	/**
	 * Clear cache and timeout queues
	 */
	public void clearCache() {
		if (cache != null) {
			cache.clear();
			isModified = true;
		}

		if (timeoutQueue != null) {
			timeoutQueue.clear();
			isModified = true;
		}
	}

	private void createCache() {
		cache =
		    Collections.synchronizedMap(new HashMap<Long, String>(cacheCapacity,
		        cacheLoadFactor));
		timeoutQueue =
		    new PriorityQueue<AbstractResolver.TimeoutEntry>(cacheCapacity,
		        new Comparator<AbstractResolver.TimeoutEntry>() {

			        public int compare(
			            AbstractResolver.TimeoutEntry o1,
			            AbstractResolver.TimeoutEntry o2) {
				        return (int) (o1.timeout - o2.timeout);
			        }

		        });

	}

	private String filename() {
		String filename =
		    this.name
		        + JConfig.getProperty(PROPERTY_CACHE_SUFFIX, DEFAULT_CACHE_SUFFIX);

		return filename;
	}

	@Override
	protected void finalize() throws Throwable {
		saveCache();

		super.finalize();
	}

	public final int getCacheCapacity() {
		return this.cacheCapacity;
	}

	public final float getCacheLoadFactor() {
		return this.cacheLoadFactor;
	}

	public final long getNegativeTimeout() {
		return this.negativeTimeout;
	}

	public final long getPositiveTimeout() {
		return this.positiveTimeout;
	}

	protected boolean hasCacheFile() {
		File file;
		try {
			file = JConfig.getFile(this.name, PROPERTY_RESOLVER_FILE_SEARCH_PATH);
		} catch (IOException e) {
			return false;
		}
		return file != null && file.canRead() && file.length() > 0;
	}

	/**
	 * Called by JRegistry when resolver when it is being retrieved. This allows
	 * the resolver to do a late initialization, only when its actually called on
	 * to do work. This behaviour is JRegistry specific and therefore kept package
	 * and subclass accessible.
	 */
	public void initializeIfNeeded() {

		if (cache == null) {
			createCache();
			
			initProperties();

			try {
				loadCache(); // Loads using default behaviour
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	private void initProperties() {
		JConfig.addListener(this, String.format(PROPERTY_POSITIVE_TIMEOUT, ""),
		    DEFAULT_POSITIVE_TIMEOUT_IN_MILLIS);
		JConfig.addListener(this, String.format(PROPERTY_NEGATIVE_TIMEOUT, ""),
		    DEFAULT_NEGATIVE_TIMEOUT_IN_MILLIS);
		JConfig.addListener(this, String.format(PROPERTY_SAVE_CACHE, ""),
		    DEFAULT_SAVE_CACHE);
		JConfig.addListener(this, String.format(PROPERTY_MAX_ENTRIES, ""),
		    DEFAULT_MAX_ENTRIES);
		JConfig.addListener(this, String.format(PROPERTY_BACKOFF, ""),
		    DEFAULT_BACKOFF);
		JConfig.addListener(this, String.format(PROPERTY_MKDIR_HOME, ""),
		    DEFAULT_MKDIR_HOME);

		/*
		 * we don't specify a default for these, as the default would cause the
		 * parent value to be always overriden. A null default will not trigger a
		 * secondary property update and thus leaving everything at the parent's
		 * default defined above.
		 */
		final String n = this.name + ".";
		JConfig
		    .addListener(this, String.format(PROPERTY_POSITIVE_TIMEOUT, n), null);
		JConfig
		    .addListener(this, String.format(PROPERTY_NEGATIVE_TIMEOUT, n), null);
		JConfig.addListener(this, String.format(PROPERTY_SAVE_CACHE, n), null);
		JConfig.addListener(this, String.format(PROPERTY_MAX_ENTRIES, n), null);
		JConfig.addListener(this, String.format(PROPERTY_BACKOFF, this.name + "."),
		    null);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see packet.format.JFormatter.Resolver#isCached(byte[])
	 */
	public boolean isCached(byte[] address) {
		return this.cache.containsKey(toHashCode(address));
	}

	/**
	 * Load cache entries using default mechanism
	 * 
	 * @return number of cache entries read
	 * @throws IOException
	 */
	public int loadCache() throws IOException {

		URL url = JConfig.getURL(this.name, RESOLVER_SEARCH_PATH_PROPERTY);
		if (url == null) {
			logger.fine("cache file " + name + " not found");
			return 0;
		}

		logger.finer("loading cache file " + url.toString());
		return loadCache(new BufferedReader(new InputStreamReader(url.openStream())));
	}

	private int loadCache(BufferedReader in) throws IOException {
		long time = System.currentTimeMillis();
		int count = 0;

		if (cache == null) {
			createCache();
		} else {
			cache.clear();
		}

		synchronized (cache) {
			try {
				boolean m = isModified; // Save the state flag

				String line;
				while ((line = in.readLine()) != null) {
					String[] c = line.split(":", 3);
					if (c.length != 3) {
						isModified = true;
						logger.fine("corrupt entry in cache file");
						continue;
					}
					long hash = Long.parseLong(c[0], 16);
					long timeout = 0;
					try {

						timeout = Long.parseLong(c[1], 16);
					} catch (NumberFormatException e) {
						m = true; // Modify flag to allow update to this cache file
						continue;
					}

					String v = (c[2].length() == 0) ? null : c[2];

					if (timeout <= time) {
						logger.fine(String.format("on load timeout, skipping %x %d\n",
						    hash, ((timeout - time) / 1000)));
						isModified = true;
						continue; // Already timedout
					}

					addToCache(hash, v, timeout - time);

					count++;
				}

				isModified = m;

			} finally {
				in.close();
			}
		}

		return count;
	}

	/**
	 * Load cache entries from file. Each cached entry is saved with a timeout
	 * timestamp. If the timeout is already expired, the entry is skipped.
	 * 
	 * @param file
	 *          file to load cache entries from
	 * @return number of entries saved
	 * @throws IOException
	 *           any IO errors
	 */
	public int loadCache(String file) throws IOException {

		File f = new File(file);
		if (f.canRead() == false) {
			return 0;
		}

		final BufferedReader in = new BufferedReader(new FileReader(f));

		return loadCache(in);
	}

	public int loadCache(URL url) throws IOException {
		return loadCache(new BufferedReader(new InputStreamReader(url.openStream())));
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.beans.PropertyChangeListener#propertyChange(java.beans.PropertyChangeEvent)
	 */
	public void propertyChange(PropertyChangeEvent evt) {

		if (String.format(PROPERTY_NEGATIVE_TIMEOUT, "").equals(
		    evt.getPropertyName())) {
			negativeTimeout = JEvent.longValue(evt);
			if (negativeTimeout == -1L) {
				negativeTimeout = INFINITE_TIMEOUT;
			}

		} else if (String.format(PROPERTY_POSITIVE_TIMEOUT, "").equals(
		    evt.getPropertyName())) {
			positiveTimeout = JEvent.longValue(evt);
			if (positiveTimeout == -1L) {
				positiveTimeout = INFINITE_TIMEOUT;
			}

		} else if (String.format(PROPERTY_SAVE_CACHE, "").equals(
		    evt.getPropertyName())) {
			saveCache = JEvent.booleanValue(evt);

		} else if (String.format(PROPERTY_MAX_ENTRIES, "").equals(
		    evt.getPropertyName())) {
			maxentries = JEvent.intValue(evt);
			if (cache.size() > maxentries) {
				timeoutCacheOldest(maxentries * 100 / backoff);
			}

		} else if (String.format(PROPERTY_BACKOFF, "")
		    .equals(evt.getPropertyName())) {
			backoff = JEvent.intValue(evt);

		} else if (String.format(PROPERTY_MKDIR_HOME, "").equals(
		    evt.getPropertyName())) {
			mkdirHome = JEvent.booleanValue(evt);

		} else if (String.format(PROPERTY_NEGATIVE_TIMEOUT, this.name + ".")
		    .equals(evt.getPropertyName())) {
			negativeTimeout = JEvent.longValue(evt);
			if (negativeTimeout == -1L) {
				negativeTimeout = INFINITE_TIMEOUT;
			}

		} else if (String.format(PROPERTY_POSITIVE_TIMEOUT, this.name + ".")
		    .equals(evt.getPropertyName())) {
			positiveTimeout = JEvent.longValue(evt);
			if (positiveTimeout == -1L) {
				positiveTimeout = INFINITE_TIMEOUT;
			}

		} else if (String.format(PROPERTY_SAVE_CACHE, this.name + ".").equals(
		    evt.getPropertyName())) {
			saveCache = JEvent.booleanValue(evt);

		} else if (String.format(PROPERTY_MAX_ENTRIES, this.name + ".").equals(
		    evt.getPropertyName())) {
			maxentries = JEvent.intValue(evt);

			if (cache.size() > maxentries) {
				timeoutCacheOldest(maxentries * 100 / backoff);

			}
		} else if (String.format(PROPERTY_BACKOFF, this.name + ".").equals(
		    evt.getPropertyName())) {
			backoff = JEvent.intValue(evt);
		}

		// System.out.printf("%s: %s %s\n", evt.getPropertyName(), logger, logger
		// .getLevel());

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see packet.format.JFormatter.Resolver#resolve(byte[])
	 */
	public final String resolve(byte[] address) {

		timeoutCache();

		long hash = toHashCode(address);
		if (cache.containsKey(hash)) {
			return cache.get(hash);
		}

		String s = resolveToName(address, hash);

		addToCache(hash, s);

		return s;
	}

	/**
	 * Resolves an address to a name. Performs any neccessary lookups to try and
	 * resolve the name. The method should not access any of the cached
	 * information. THis method is called only after the cache has already been
	 * checked and failed to produce a positive or negative lookup entry.
	 * 
	 * @param address
	 *          address to resolve
	 * @param hash
	 *          computed hash code for the address, identifies the address
	 *          uniquely
	 */
	protected abstract String resolveToName(byte[] address, long hash);

	/**
	 * Resolves number to a name. Performs any neccessary lookups to try and
	 * resolve the name. The method should not access any of the cached
	 * information. THis method is called only after the cache has already been
	 * checked and failed to produce a positive or negative lookup entry.
	 * 
	 * @param number
	 *          a number value to resolve
	 * @param hash
	 *          computed hash code for the number, identifies the number uniquely
	 */
	protected abstract String resolveToName(long number, long hash);

	/**
	 * Save the cache using default mechanism, if set
	 * 
	 * @return number of cache entries saved
	 * @throws IOException
	 */
	public int saveCache() throws IOException {
		timeoutCache();

		if (saveCache == false || isModified == false || timeoutQueue.isEmpty()) {
			return 0;
		}

		URL url = JConfig.getURL(this.name, RESOLVER_SEARCH_PATH_PROPERTY);

		if (url == null) {
			logger.fine("cache file " + name + " not found");

			File dir = JConfig.getDir(PROPERTY_RESOLVER_HOME_SEARCH_PATH);
			if (dir == null) {
				logger.fine("cache directory not found");

				if (mkdirHome == true) {

					logger.fine("attempting to create cache directory using property "
					    + PROPERTY_RESOLVER_HOME);
					dir = JConfig.createDir(PROPERTY_RESOLVER_HOME, DEFAULT_HOME);
					if (dir == null) {
						return 0;
					}
				} else {
					logger.finer("property resolver.home.mkdir set to false, giving up");
					return 0;
				}
			}
			url = new File(dir, filename()).toURL();
		}

		logger.finer("saving cache " + url.toString());

		int count =
		    saveCache(new PrintWriter(new OutputStreamWriter(new FileOutputStream(
		        url.getFile()))));
		if (count == 0) {
			throw new IllegalStateException("Saved empty cache");
		}

		return count;
	}

	private int saveCache(PrintWriter out) {
		int count = 0;

		logger.finer(String.format("saving %d entries", cache.size()));

		synchronized (cache) {
			try {
				/*
				 * We use the timeout queue to save the cache. All entries in cache are
				 * also in the timeout queue.
				 */
				for (Iterator<AbstractResolver.TimeoutEntry> i =
				    timeoutQueue.iterator(); i.hasNext();) {
					final AbstractResolver.TimeoutEntry e = i.next();
					String v = cache.get(e.hash);

					if (logger.isLoggable(Level.FINEST)) {
						logger.finest(String.format("saving %X %X\n", e.hash,
						    (e.timeout - System.currentTimeMillis())));
					}

					out.format("%X:%d:%s" + NEWLINE_SEPARATOR, e.hash, e.timeout,
					    (v == null) ? "" : v);
					count++;
				}

			} finally {
				out.close();
			}
		}

		return count;
	}

	/**
	 * Save the cache to file.
	 * 
	 * @param file
	 *          file to save to
	 * @return number of entries saved
	 * @throws IOException
	 *           any IO errors
	 */
	public int saveCache(String file) throws IOException {
		File f = new File(file);
		if (f.exists()) {
			f.delete();
		}

		if (f.createNewFile() == false) {
			return 0;
		}

		final PrintWriter out = new PrintWriter(new FileWriter(f));

		return saveCache(out);
	}

	public final void setCacheCapacity(int cacheCapacity) {
		this.cacheCapacity = cacheCapacity;
	}

	public final void setCacheLoadFactor(float cacheLoadFactor) {
		this.cacheLoadFactor = cacheLoadFactor;
	}

	public final void setNegativeTimeout(long negativeTimeout) {
		JConfig.setProperty(String.format(PROPERTY_NEGATIVE_TIMEOUT, this.name
		    + "."), Long.toString(negativeTimeout));
	}

	public final void setPositiveTimeout(long positiveTimeout) {
		JConfig.setProperty(String.format(PROPERTY_POSITIVE_TIMEOUT, this.name
		    + "."), Long.toString(positiveTimeout));
	}

	private void timeoutCache() {
		final long t = System.currentTimeMillis();

		synchronized (cache) {
			for (Iterator<AbstractResolver.TimeoutEntry> i = timeoutQueue.iterator(); i
			    .hasNext();) {
				AbstractResolver.TimeoutEntry e = i.next();
				if (e.timeout < t) {
					System.out.printf("%s: %s %s\n", "timeout()", logger, logger
					    .getLevel());
					logger.finest(String.format("timedout %s\n", cache.get(e.hash)));
					cache.remove(e.hash);
					i.remove();
				} else {
					break;
				}
			}
		}
	}

	/**
	 * Removes count oldest entries from the timeout cache, presumably to make
	 * room for newer entries.
	 * 
	 * @param count
	 */
	private void timeoutCacheOldest(int count) {
		synchronized (cache) {
			for (Iterator<AbstractResolver.TimeoutEntry> i = timeoutQueue.iterator(); i
			    .hasNext();) {
				AbstractResolver.TimeoutEntry e = i.next();
				if (count-- > 0) {
					logger.finest(String.format("removed due to backoff %s \n", cache
					    .get(e.hash)));
					cache.remove(e.hash);
					i.remove();
				} else {
					break;
				}
			}
		}
	}

	protected abstract long toHashCode(byte[] address);

	protected long toHashCode(long number) {
		return number;
	}

	public String toString() {
		StringBuilder out = new StringBuilder();
		out.append(String.format("cache[count=%d], "
		    + "timeout[count=%d, positive=%d, negative=%d], ", cache.size(),
		    timeoutQueue.size(), positiveTimeout, negativeTimeout));
		return out.toString();
	}
}