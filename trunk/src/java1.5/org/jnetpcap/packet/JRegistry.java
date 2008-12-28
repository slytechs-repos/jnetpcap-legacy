package org.jnetpcap.packet;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Formatter;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.Queue;

import org.jnetpcap.PcapDLT;
import org.jnetpcap.packet.format.JFormatter;
import org.jnetpcap.packet.structure.AnnotatedBinding;
import org.jnetpcap.packet.structure.AnnotatedHeader;
import org.jnetpcap.packet.structure.AnnotatedScannerMethod;
import org.jnetpcap.packet.structure.HeaderDefinitionError;

/**
 * A registry of protocols, their classes, runtime IDs and bindings. This is a
 * global registry that all of jnetpcap's packet framework accesses. The
 * registry matains tables of bindings, header scanners and numerical IDs for
 * each header. The registry also performs various lookup and cross reference
 * infomatation such as mapping a header class to a numerical ID.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("unchecked")
public final class JRegistry {

	/**
	 * Default adaptor class for Resovler interface. This abstract class provides
	 * the default caching mechanism for positive and negative resolver lookups.
	 * It also provides a timeout mechanism to time out lookup results.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public abstract static class AbstractResolver implements Resolver {

		private static class TimeoutEntry {
			public int key;

			public long timeout;

			/**
			 * @param key
			 */
			public TimeoutEntry(int key, long timeout) {
				this.key = key;
				timeout = System.currentTimeMillis() + timeout;
			}
		}

		/**
		 * Default timeout interval in milli seconds for a negative lookup entry
		 * (Default is 30 seconds)
		 */
		public static final long DEFAULT_NEGATIVE_TIMEOUT_IN_MILLIS = 30 * 1000;

		/**
		 * Default timeout interval in milli seconds for a positive lookup entry
		 * (Defalt is 30 minutes)
		 */
		public static final long DEFAULT_POSITIVE_TIMEOUT_IN_MILLIS =
		    60 * 1000 * 30; // 30 minutes

		private Map<Integer, String> cache;

		private int cacheCapacity = 100;

		private float cacheLoadFactor = 0.75f;

		private long negativeTimeout = DEFAULT_NEGATIVE_TIMEOUT_IN_MILLIS;

		private long positiveTimeout = DEFAULT_POSITIVE_TIMEOUT_IN_MILLIS;

		private Queue<TimeoutEntry> timeoutQueue;

		public AbstractResolver(ResolverType type) {
			this(type.name());
		}

		public AbstractResolver(String name) {
			if (name == null || name.length() == 0) {
				throw new IllegalArgumentException("resolver's name must be set");
			}

			loadCache(); // Loads using default behaviour
		}

		public void addToCache(int hash, String name) {

			if (name == null && negativeTimeout == 0 || name != null
			    && positiveTimeout == 0) {
				return; // Don't cache
			}

			cache.put(hash, name);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.format.JFormatter.Resolver#isResolved(byte[])
		 */
		public boolean canBeResolved(byte[] address) {
			return resolve(address) != null;
		}

		@Override
		protected void finalize() throws Throwable {
			saveCache();
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

		/**
		 * Called by JRegistry when resolver when it is being retrieved. This allows
		 * the resolver to do a late initialization, only when its actually called
		 * on to do work. This behaviour is JRegistry specific and therefore kept
		 * package and subclass accessible.
		 */
		public void initializeIfNeeded() {

			if (cache == null) {
				cache = new HashMap<Integer, String>(cacheCapacity, cacheLoadFactor);
				timeoutQueue =
				    new PriorityQueue<TimeoutEntry>(cacheCapacity,
				        new Comparator<TimeoutEntry>() {

					        public int compare(TimeoutEntry o1, TimeoutEntry o2) {
						        return (int) (o1.timeout - o2.timeout);
					        }

				        });
			}

		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.format.JFormatter.Resolver#isCached(byte[])
		 */
		public boolean isCached(byte[] address) {
			return this.cache.containsKey(toHashCode(address));
		}

		/**
		 * Load cache entries using default mechanism
		 * 
		 * @return number of cache entries read
		 */
		public int loadCache() {
			// TODO: add default cache loading conditions and behaviour
			return 0;
		}

		private int loadCache(BufferedReader in) throws IOException {
			long time = System.currentTimeMillis();
			int count = 0;

			try {
				String line;
				while ((line = in.readLine()) != null) {
					String[] c = line.split(":", 3);
					if (c.length != 3) {
						continue;
					}
					int hash = Integer.parseInt(c[0], 16);
					Long timeout = (time - Long.parseLong(c[1], 16));
					String v = (c[2].length() == 0) ? null : c[2];

					if (timeout <= 0) {
						continue; // Already timedout
					}

					timeoutQueue.add(new TimeoutEntry(hash, timeout));
					addToCache(hash, v);

					count++;
				}

			} finally {
				in.close();
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
			return loadCache(new BufferedReader(new InputStreamReader(url
			    .openStream())));
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.format.JFormatter.Resolver#resolve(byte[])
		 */
		public final String resolve(byte[] address) {

			timeoutCache();

			int hash = toHashCode(address);
			String s = cache.get(hash);
			if (cache.containsKey(hash)) {
				return s;
			}

			s = resolveToName(address, hash);

			addToCache(hash, s);

			if (s == null) {
				timeoutQueue.add(new TimeoutEntry(hash, negativeTimeout));
			}
			{
				timeoutQueue.add(new TimeoutEntry(hash, positiveTimeout));
			}

			return s;
		}

		/**
		 * @param address
		 * @param hash
		 */
		protected abstract String resolveToName(byte[] address, int hash);

		/**
		 * Save the cache using default mechanism, if set
		 * 
		 * @return number of cache entries saved
		 */
		public int saveCache() {
			// TODO: add default cache saving conditions and behaviour
			return 0;
		}

		private int saveCache(PrintWriter out) {
			int count = 0;

			try {
				/*
				 * We use the timeout queue to save the cache. All entries in cache are
				 * also in the timeout queue.
				 */
				for (Iterator<TimeoutEntry> i = timeoutQueue.iterator(); i.hasNext();) {
					final TimeoutEntry e = i.next();
					String v = cache.get(e.key);

					out.format("%X:%X:%s\n", e.key, e.timeout, (v == null) ? "" : v);
					count++;
				}

			} finally {
				out.close();
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
			timeoutCache();

			File f = new File(file);
			if (f.canWrite() == false) {
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
			this.negativeTimeout = negativeTimeout;
		}

		public final void setPositiveTimeout(long positiveTimeout) {
			this.positiveTimeout = positiveTimeout;
		}

		private void timeoutCache() {
			final long t = System.currentTimeMillis();

			for (Iterator<TimeoutEntry> i = timeoutQueue.iterator(); i.hasNext();) {
				TimeoutEntry e = i.next();
				if (e.timeout < t) {
					// System.out.printf("timedout %s\n", cache.get(e.key));
					cache.remove(e.key);
					i.remove();
				} else {
					break;
				}
			}
		}

		protected abstract int toHashCode(byte[] address);

		public String toString() {
			StringBuilder out = new StringBuilder();
			out.append(String.format("cache[count=%d], "
			    + "timeout[count=%d, positive=%d, negative=%d], ", cache.size(),
			    positiveTimeout, negativeTimeout));
			return out.toString();
		}
	}

	/**
	 * A header information entry created for every header registered. Entry class
	 * contains various bits and pieces of information about the registred header.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	private static class Entry {
		private AnnotatedHeader annotatedHeader;

		private final String className;

		private Class<? extends JHeader> clazz;

		private final int id;

		/**
		 * @param id
		 * @param c
		 */
		public Entry(int id, Class<? extends JHeader> c) {
			this.id = id;
			this.clazz = c;
			this.className = c.getName();
		}

		public Entry(int id, String className) {
			this.id = id;
			this.className = className;
		}

		public Class<? extends JHeader> getHeaderClass() {
			if (clazz == null) {
				try {
					return (Class<? extends JHeader>) Class.forName(className);
				} catch (ClassNotFoundException e) {
					throw new IllegalStateException(e);
				}
			} else {
				return this.clazz;
			}
		}
	}

	/**
	 * A resolver that resolves the first 3 bytes of a MAC address to a
	 * manufacturer code. The resolver loads jNetPcap supplied compressed oui
	 * database of manufacturer codes and caches that information. The resolver
	 * can also download over the internet, if requested, a raw IEEE OUI database
	 * of manufacturer code, parse it and produce a cache file for future use.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	private static class IEEEOuiPrefixResolver
	    extends AbstractResolver {

		public final static String IEEE_OUI_DATABASE_PATH =
		    "http://standards.ieee.org/regauth/oui/oui.txt";

		private boolean initialized = false;

		/**
		 * @param type
		 */
		public IEEEOuiPrefixResolver() {
			super("IEEE_OUI_PREFIX");
		}

		@Override
		public void initializeIfNeeded() {
			if (initialized == false) {
				initialized = true;

				setCacheCapacity(13000); // There are over 12,000 entries in the db
				setPositiveTimeout(Long.MAX_VALUE - System.currentTimeMillis()); // Never

				setNegativeTimeout(0); // Never cache

				super.initializeIfNeeded(); // Allow the baseclass to prep cache

				try {
					readOuisFromCompressedIEEEDb("oui.txt");
				} catch (FileNotFoundException e) {
				} catch (IOException e) {
				}
			}
		}

		@Override
		public int loadCache(URL url) throws IOException {
			return readOuisFromRawIEEEDb(new BufferedReader(new InputStreamReader(url
			    .openStream())));
		}

		private int readOuisFromCompressedIEEEDb(BufferedReader in)
		    throws IOException {
			int count = 0;

			try {
				String s;
				while ((s = in.readLine()) != null) {
					String[] c = s.split(":");
					if (c.length < 2) {
						continue;
					}

					int i = Integer.parseInt(c[0], 16);

					super.addToCache(i, c[1]);
					count++;

				}
			} finally {
				in.close(); // Make sure we close the file
			}

			return count;
		}

		private boolean readOuisFromCompressedIEEEDb(String f)
		    throws FileNotFoundException, IOException {
			/*
			 * Try local file first, more efficient
			 */
			File file = new File(f);
			if (file.canRead()) {
				readOuisFromCompressedIEEEDb(new BufferedReader(new FileReader(file)));
				return true;
			}

			/*
			 * Otherwise look for it in classpath
			 */
			InputStream in =
			    JFormatter.class.getClassLoader().getResourceAsStream(
			        "resources/" + f);
			if (in == null) {
				return false; // Can't find it
			}
			readOuisFromCompressedIEEEDb(new BufferedReader(new InputStreamReader(in)));

			return true;
		}

		private int readOuisFromRawIEEEDb(BufferedReader in) throws IOException {
			int count = 0;
			try {
				String s;
				while ((s = in.readLine()) != null) {
					if (s.contains("(base 16)")) {
						String[] c = s.split("\t\t");
						if (c.length < 2) {
							continue;
						}

						String p = c[0].split(" ")[0];
						int i = Integer.parseInt(p, 16);
						String[] a = c[1].split(" ");

						if (a.length > 0) {
							super.addToCache(i, a[1]);
							count++;
						}
					}
				}
			} finally {
				in.close(); // Make sure we close the file
			}

			return count;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.JRegistry.AbstractResolver#resolveToName(byte[],
		 *      int)
		 */
		@Override
		public String resolveToName(byte[] address, int hash) {
			return null; // If its not in the cache, we don't know what it is
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.JRegistry.AbstractResolver#toHashCode(byte[])
		 */
		@Override
		public int toHashCode(byte[] address) {
			return ((address[2] < 0) ? address[2] + 256 : address[2])
			    | ((address[1] < 0) ? address[1] + 256 : address[1]) << 8
			    | ((address[0] < 0) ? address[0] + 256 : address[0]) << 16;
		}
	}

	/**
	 * Default IP resolver that JRegistry uses
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	private static class IpResolver
	    extends AbstractResolver {

		/**
		 * @param type
		 */
		public IpResolver() {
			super("IP");
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.format.JFormatter.AbstractResolver#resolveToName(byte[],
		 *      int)
		 */
		@Override
		public String resolveToName(byte[] address, int hash) {
			try {
				InetAddress i = InetAddress.getByAddress(address);
				String host = i.getHostName();
				if (Character.isDigit(host.charAt(0)) == false) {
					addToCache(hash, host);
					return host;
				}

			} catch (UnknownHostException e) {
				e.printStackTrace();
			}
			return null;

		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.format.JFormatter.AbstractResolver#toHashCode(byte[])
		 */
		@Override
		public int toHashCode(byte[] address) {
			int hash =
			    ((address[3] < 0) ? address[3] + 256 : address[3])
			        | ((address[2] < 0) ? address[2] + 256 : address[2]) << 8
			        | ((address[1] < 0) ? address[1] + 256 : address[1]) << 16
			        | ((address[0] < 0) ? address[0] + 256 : address[0]) << 24;

			return hash;
		}

	}

	/**
	 * A resolver interface that can resolver various types of addresses and
	 * specific protocol numbers and types to a human readable name. The resolver
	 * will do an appropriate type of look up is appropriate for a given protocol,
	 * to try and map a binary entity to a human assigned and readable one.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public interface Resolver {
		/**
		 * Checks if a mapping exists or can be made. This operation may trigger a
		 * lookup which may take certain amount of time to complete, some times many
		 * seconds or even minutes.
		 * 
		 * @param address
		 *          address to check mapping for
		 * @return true the mapping can be made, otherwise false
		 */
		public boolean canBeResolved(byte[] address);

		/**
		 * 
		 */
		public void initializeIfNeeded();

		/**
		 * Checks if resolver already has a mapping made for this particular
		 * address. This operation does not block and returns immediately. The
		 * mapping may include a negative lookup, one that failed before. None the
		 * less the negative result is cached along with positive results.
		 * 
		 * @param address
		 *          address to check for
		 * @return true if mapping is already cached, otherwise false
		 */
		public boolean isCached(byte[] address);

		/**
		 * Attempts to resoler an address to a human readable form. Any possible or
		 * required look ups are performed, sometimes taking a long time to complete
		 * if neccessary. All results, positive and negative for the lookup, are
		 * cached for certain amount of time.
		 * 
		 * @param address
		 *          address to try and resolve
		 * @return human readable form if lookup succeeded (position) or null if
		 *         lookup failed to produce a human label (negative)
		 */
		public String resolve(byte[] address);
	}

	/**
	 * Type of resolver that can be registered with JRegistry. Resolvers job is to
	 * convert a binary number to a human readable name associated with it. For
	 * example IP resolver will convert ip address to hostnames.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum ResolverType {
		/**
		 * Converts MAC addresses to station names when defined
		 */
		IEEE_OUI_ADDRESS,

		/**
		 * Converts a MAC address manufacturer prefix to a name
		 */
		IEEE_OUI_PREFIX(new IEEEOuiPrefixResolver()),

		/**
		 * Converts Ip version 4 and 6 address to hostnames and constant labels
		 */
		IP(new IpResolver()),

		/**
		 * Converts TCP and UDP port numbers to application names
		 */
		PORT, ;

		private final Resolver resolver;

		private ResolverType() {
			this.resolver = null;
		}

		private ResolverType(Resolver resolver) {
			this.resolver = resolver;
		}

		public final Resolver getResolver() {
			return this.resolver;
		}
	}

	/**
	 * A private duplicate constant for MAX_ID_COUNT who's name is prefixed with
	 * A_ so that due to source code sorting, we don't get compiler errors. Made
	 * private so no one outside this class knows about it. Got tired of having to
	 * move MAX_ID_COUNT definition around after each source sort.
	 */
	private final static int A_MAX_ID_COUNT = 64;

	/**
	 * Number of core protocols defined by jNetPcap
	 */
	@SuppressWarnings("unused")
	public static final int CORE_ID_COUNT = JProtocol.values().length;

	private final static int[] DLTS_TO_IDS;

	private static List<HeaderDefinitionError> errors =
	    new ArrayList<HeaderDefinitionError>();

	/**
	 * A flag that allows tells that a java scanner's process bindings method has
	 * been overriden
	 */
	public final static int FLAG_OVERRIDE_BINDING = 0x00000002;

	/**
	 * A flag that allows tells that a java scanner's get length method has been
	 * overriden
	 */
	public final static int FLAG_OVERRIDE_LENGTH = 0x00000001;

	private final static int headerFlags[] = new int[A_MAX_ID_COUNT];

	private final static int[] IDS_TO_DLTS;

	private static int LAST_ID = JProtocol.values().length;

	private final static Entry[] MAP_BY_ID = new Entry[A_MAX_ID_COUNT];

	/**
	 * Holds class to ID mapping - this is global accross all registries
	 */
	private static Map<String, Entry> mapByClassName =
	    new HashMap<String, Entry>();

	private static Map<String, AnnotatedHeader> mapSubsByClassName =
	    new HashMap<String, AnnotatedHeader>(50);

	private static final int MAX_DLT_COUNT = 512;

	/**
	 * Maximum number of protocol header entries allowed by this implementation of
	 * JRegistry
	 */
	public final static int MAX_ID_COUNT = 64;

	/**
	 * A constant if returned from {@link #mapDltToId} or {@link #mapIdToDLT} that
	 * no mapping exists.
	 */
	public static final int NO_DLT_MAPPING = -1;

	/**
	 * Allow any type of key to be used so that users can register their own
	 * unknown type resolvers
	 */
	private final static Map<Object, Resolver> resolvers =
	    new HashMap<Object, Resolver>();

	/**
	 * Header scanners for each header type and protocol. The user can override
	 * native direct scanners by supplying a java based scanner that will override
	 * a particular protocols entry.
	 */
	private final static JHeaderScanner[] scanners =
	    new JHeaderScanner[A_MAX_ID_COUNT];

	/**
	 * Initialize JRegistry with defaults
	 * <ul>
	 * <li> libpcap DLT mappings</li>
	 * <li> Register CORE protocols</li>
	 * <li> Register address resolvers</li>
	 * </ul>
	 */
	static {

		/**
		 * Initialized DLT to ID mappings
		 */
		DLTS_TO_IDS = new int[MAX_DLT_COUNT];
		IDS_TO_DLTS = new int[MAX_ID_COUNT];

		Arrays.fill(JRegistry.DLTS_TO_IDS, -1);
		Arrays.fill(JRegistry.IDS_TO_DLTS, -1);

		/**
		 * Register CORE protocols
		 */
		for (JProtocol p : JProtocol.values()) {

			try {
				register(p);
			} catch (Exception e) {
				System.err.println("JRegistry Error: " + e.getMessage());
				e.printStackTrace();

				System.exit(0);
			}
		}

		/**
		 * Register default resolvers for address to name mappings
		 */
		for (ResolverType t : ResolverType.values()) {
			if (t.getResolver() != null) {
				try {
					registerResolver(t, t.getResolver());
				} catch (Exception e) {
					System.err.println("JRegistry Error: " + e.getMessage());
					e.printStackTrace();

					System.exit(0);
				}
			}
		}
	}

	/**
	 * Adds bindings found in the container class. Any static methods that have
	 * the <code>Bind</code> annotation defined will be extracted and wrapped as
	 * <code>JBinding</code> interface objects, suitable to be registered with
	 * for a target header. Bindings contained in any class that does not extend
	 * <code>JHeader</code> is required to provide both "to" and "from"
	 * parameters to <code>Bind</code> annotation.
	 * 
	 * @param container
	 *          container that has static bind methods
	 */
	public static void addBindings(Class<?> container) {
		clearErrors();

		if (JHeader.class.isAssignableFrom(container)) {
			addBindings(AnnotatedBinding.inspectJHeaderClass(
			    (Class<? extends JHeader>) container, errors));

		} else {
			addBindings(AnnotatedBinding.inspectClass(container, errors));
		}
	}

	/**
	 * Adds additional bindings to a particular protocol
	 * 
	 * @param id
	 * @param bindings
	 */
	public static void addBindings(JBinding... bindings) {

		for (JBinding b : bindings) {
			scanners[b.getTargetId()].addBindings(b);
		}

	}

	/**
	 * Adds all of the bindings found in the bindinsContainer object supplied. The
	 * methods that have the <code>Bind</code> annotation, will be extracted and
	 * converted to JBinding objects that will call on those methods as a binding.
	 * The "this" pointer in the instance methods will be set to null, therefore
	 * do not rely on any super methods and "this" operator. The bind annotation
	 * inspector check and ensure that only "Object" class is extended for the
	 * container class.
	 * 
	 * @param bindingContainer
	 *          container object that contains binding instance methods
	 */
	public static void addBindings(Object bindingContainer) {
		clearErrors();
		addBindings(AnnotatedBinding.inspectObject(bindingContainer, errors));
	}

	/**
	 * Clears any existing registery errors
	 */
	public static void clearErrors() {
		errors.clear();
	}

	/**
	 * Clears the supplied bits within the flag's bitmap
	 * 
	 * @param id
	 *          protocol ID
	 * @param flags
	 *          flags to clear
	 */
	public static void clearFlags(int id, int flags) {
		headerFlags[id] &= ~flags;
	}

	/**
	 * Clears java scanners for supplied list of headers
	 * 
	 * @param classes
	 *          classes of all the headers that java scanner will be cleared if
	 *          previously registered
	 */
	public static void clearScanners(Class<? extends JHeader>... classes) {
		for (Class<? extends JHeader> c : classes) {
			int id = lookupId(c);

			scanners[id].setScannerMethod(null);
		}
	}

	/**
	 * Clears java scanners for supplied list of headers
	 * 
	 * @param ids
	 *          ids of all the headers that java scanner will be cleared if
	 *          previously registered
	 */
	public static void clearScanners(int... ids) {
		for (int id : ids) {
			scanners[id].setScannerMethod(null);
		}
	}

	/**
	 * Removes previously registered scanners that are defined in the supplied
	 * object container. Any scanners within the supplied container are retrieved
	 * and all the currently registered java scanner for the headers that the
	 * retrieved scanners target, are cleared.
	 * 
	 * @param container
	 *          container object containing scanner methods which target headers
	 *          that will be cleared of java scanners
	 */
	public static void clearScanners(Object container) {
		AnnotatedScannerMethod[] methods =
		    AnnotatedScannerMethod.inspectObject(container);

		int[] ids = new int[methods.length];

		for (int i = 0; i < ids.length; i++) {
			ids[i] = methods[i].getId();
		}

		clearScanners(ids);
	}

	/**
	 * Creates a new header entry for storing information about a header
	 * 
	 * @param c
	 *          header class
	 * @return newly created entry
	 */
	private static Entry createNewEntry(Class<? extends JHeader> c) {
		int id = LAST_ID;
		Entry e;
		mapByClassName.put(c.getCanonicalName(), e = new Entry(id, c));
		MAP_BY_ID[id] = e;

		LAST_ID++;

		return e;
	}

	/**
	 * Retrieves all current bindings bound to a protocol
	 * 
	 * @param id
	 *          protocol id
	 * @return array of bindings for this protocol
	 */
	public static JBinding[] getBindings(int id) {
		return scanners[id].getBindings();
	}

	/**
	 * Retrieves the recent errors that were generated by registry operations
	 * 
	 * @return array of errors
	 */
	public static HeaderDefinitionError[] getErrors() {
		return errors.toArray(new HeaderDefinitionError[errors.size()]);
	}

	/**
	 * Gets the current flags for a specified protocol
	 * 
	 * @param id
	 *          numerical id of the protocol header
	 * @return current flags as a bit mask
	 */
	public static int getFlags(int id) {
		return headerFlags[id];
	}

	/**
	 * Retrieves the entire list of scanners for all registered protocols
	 * 
	 * @return array of header scanners
	 */
	public static JHeaderScanner[] getHeaderScanners() {
		JHeaderScanner[] s = new JHeaderScanner[MAX_ID_COUNT];
		System.arraycopy(scanners, 0, s, 0, MAX_ID_COUNT);

		return s;
	}

	/**
	 * Retrieves a registered instance of any resolver.
	 * 
	 * @param customType
	 *          resolver type
	 * @return currently registered resolver
	 */
	public static Resolver getResolver(Object customType) {
		Resolver resolver = resolvers.get(customType);

		resolver.initializeIfNeeded();

		return resolver;
	}

	/**
	 * Retrieves a registered instance of a resolver.
	 * 
	 * @param type
	 *          resolver type
	 * @return currently registered resolver
	 */
	public static Resolver getResolver(ResolverType type) {
		return getResolver((Object) type);
	}

	/**
	 * Checks if a mapping for libpcap dlt value is defined
	 * 
	 * @param dlt
	 *          value to check for
	 * @return true if dlt mapping exists, otherwise false
	 */
	public static boolean hasDltMapping(int dlt) {
		return dlt >= 0 && dlt < DLTS_TO_IDS.length
		    && DLTS_TO_IDS[dlt] != NO_DLT_MAPPING;
	}

	/**
	 * Checks if there are any registry errors that were recently generated
	 * 
	 * @return true if error queue is not empty
	 */
	public static boolean hasErrors() {
		return errors.isEmpty();
	}

	/**
	 * Checks if resolver of specific type is currently registered
	 * 
	 * @param type
	 *          type of resolver to check for
	 * @return true if resolver is registered, otherwise false
	 */
	public static boolean hasResolver(Object type) {
		return resolvers.containsKey(type);
	}

	/**
	 * Checks if resolver of specific type is currently registered
	 * 
	 * @param type
	 *          type of resolver to check for
	 * @return true if resolver is registered, otherwise false
	 */
	public static boolean hasResolver(ResolverType type) {
		return resolvers.containsKey(type);
	}

	public static AnnotatedHeader inspect(
	    Class<? extends JHeader> c,
	    List<HeaderDefinitionError> errors) {

		return AnnotatedHeader.inspectJHeaderClass(c, errors);
	}

	/**
	 * Returns a complete list of currently active resolvers types.
	 * 
	 * @return
	 */
	public static Object[] listResolvers() {
		return resolvers.keySet().toArray(new Object[resolvers.size()]);
	}

	public static AnnotatedHeader lookupAnnotatedHeader(Class<? extends JHeader> c)
	    throws UnregisteredHeaderException {

		if (JSubHeader.class.isAssignableFrom(c)) {
			return lookupAnnotatedSubHeader(c.asSubclass(JSubHeader.class));
		}

		return lookupAnnotatedHeader(lookupIdNoCreate(c));
	}

	public static AnnotatedHeader lookupAnnotatedHeader(int id)
	    throws UnregisteredHeaderException {
		if (MAP_BY_ID[id] == null || MAP_BY_ID[id].annotatedHeader == null) {
			throw new UnregisteredHeaderException("header [" + id
			    + "] not registered");
		}

		return MAP_BY_ID[id].annotatedHeader;
	}

	/**
	 * @param protocol
	 * @return
	 */
	public static AnnotatedHeader lookupAnnotatedHeader(JProtocol protocol) {
		Class<? extends JHeader> c = protocol.getHeaderClass();
		Entry e = MAP_BY_ID[protocol.getId()];

		if (e.annotatedHeader == null) {
			errors.clear();
			e.annotatedHeader = inspect(c, errors);

			registerAnnotatedSubHeaders(e.annotatedHeader.getHeaders());
		}

		return e.annotatedHeader;
	}

	static AnnotatedHeader lookupAnnotatedSubHeader(Class<? extends JSubHeader> c) {
		if (mapSubsByClassName.containsKey(c.getCanonicalName()) == false) {
			throw new UnregisteredHeaderException("sub header [" + c.getName()
			    + "] not registered, most likely parent not registered as well");
		}

		return mapSubsByClassName.get(c.getCanonicalName());
	}

	/**
	 * Looks up the class of a header based on its ID.
	 * 
	 * @param id
	 *          protocol id
	 * @return class for this protocol
	 * @throws UnregisteredHeaderException
	 * @throws UnregisteredHeaderException
	 *           thrown if protocol not found, invalid ID
	 */
	public static Class<? extends JHeader> lookupClass(int id)
	    throws UnregisteredHeaderException {

		if (id > LAST_ID) {
			throw new UnregisteredHeaderException("invalid id " + id);
		}

		final Entry entry = MAP_BY_ID[id];

		if (entry == null) {
			throw new UnregisteredHeaderException("invalid id " + id);
		}

		return entry.getHeaderClass();
	}

	/**
	 * Look's up the protocol header ID using a class name
	 * 
	 * @param c
	 *          class of the header
	 * @return numerical ID of the protocol header
	 * @throws UnregisteredHeaderException
	 *           if header class is not registered
	 */
	public static int lookupId(Class<? extends JHeader> c) {

		if (JSubHeader.class.isAssignableFrom(c)) {
			AnnotatedHeader header =
			    lookupAnnotatedSubHeader(c.asSubclass(JSubHeader.class));

			return header.getId();
		}

		Entry e = mapByClassName.get(c.getCanonicalName());
		if (e == null) {
			e = createNewEntry(c);
		}

		return e.id;
	}

	/**
	 * Look's up the protocol header ID using a protocol constant. This method
	 * does not throw any exception since all core protocols defined on Jprotocol
	 * table are guarrantted to be registered.
	 * 
	 * @param p
	 *          protocol constant
	 * @return numerical ID of the protocol header
	 */
	public static int lookupId(JProtocol p) {
		return p.getId();
	}

	private static int lookupIdNoCreate(Class<? extends JHeader> c)
	    throws UnregisteredHeaderException {
		if (mapByClassName.containsKey(c.getCanonicalName()) == false) {
			throw new UnregisteredHeaderException("header [" + c.getName()
			    + "] not registered");
		}

		return mapByClassName.get(c.getCanonicalName()).id;
	}

	/**
	 * Looks up a header scanner.
	 * 
	 * @param id
	 *          id of the scanner to lookup
	 * @return header scanner for this ID
	 */
	public static JHeaderScanner lookupScanner(int id) {
		return scanners[id];
	}

	public static int mapDLTToId(int dlt) {
		return DLTS_TO_IDS[dlt];
	}

	public static int mapIdToDLT(int id) {
		return IDS_TO_DLTS[id];
	}

	public static PcapDLT mapIdToPcapDLT(int id) {
		return PcapDLT.valueOf(IDS_TO_DLTS[id]);
	}

	public static int register(Class<? extends JHeader> c)
	    throws RegistryHeaderErrors {

		List<HeaderDefinitionError> errors = new ArrayList<HeaderDefinitionError>();

		int id = register(c, errors);

		if (errors.isEmpty() == false) {
			throw new RegistryHeaderErrors(c, errors, "while trying to register "
			    + c.getSimpleName() + " class");
		}

		return id;
	}

	/**
	 * Registeres a new protocol header. A new numerical ID is assigned to the
	 * protocol and various mappings are recorded for this protocol.
	 * 
	 * @param <T>
	 *          header class type
	 * @param c
	 *          class of the header
	 * @param scan
	 *          header scanner that will perform header scans and check bindings
	 * @param bindings
	 *          protocol to protocol bindings for this protocol
	 * @return numerical id assigned to this new protocol
	 * @throws RegistryHeaderErrors
	 */
	public static int register(
	    Class<? extends JHeader> c,
	    List<HeaderDefinitionError> errors) {

		AnnotatedHeader annotatedHeader = inspect(c, errors);
		JBinding[] bindings = AnnotatedBinding.inspectJHeaderClass(c, errors);
		if (errors.isEmpty() == false) {
			return -1;
		}

		Entry e = mapByClassName.get(c.getCanonicalName());
		if (e == null) {
			e = createNewEntry(c);
		}

		int id = e.id;
		e.annotatedHeader = annotatedHeader;

		scanners[id] = new JHeaderScanner(c);

		registerAnnotatedSubHeaders(annotatedHeader.getHeaders());

		addBindings(bindings);

		for (PcapDLT d : annotatedHeader.getDlt()) {
			registerDLT(d, id);
		}

		return id;
	}

	/**
	 * Registeres the core protocols. Not user accessible as this is done by
	 * default for all core protocols.
	 * 
	 * @param protocol
	 *          core protocol
	 * @return id of the core protocol, should be the same as ID pre-assigned in
	 *         JProtocol table
	 */
	static int register(JProtocol protocol) {

		Entry e = new Entry(protocol.getId(), protocol.getHeaderClassName());
		mapByClassName.put(protocol.getHeaderClassName(), e);
		MAP_BY_ID[protocol.getId()] = e;

		scanners[protocol.getId()] = new JHeaderScanner(protocol);

		for (PcapDLT d : protocol.getDlt()) {
			registerDLT(d, protocol.getId());
		}

		return protocol.getId();
	}

	private static void registerAnnotatedSubHeaders(AnnotatedHeader[] subs) {
		for (AnnotatedHeader c : subs) {
			mapSubsByClassName.put(c.getHeaderClass().getCanonicalName(), c);

			registerAnnotatedSubHeaders(c.getHeaders());
		}
	}

	public static void registerDLT(int dlt, int id) {
		DLTS_TO_IDS[dlt] = id;
		IDS_TO_DLTS[id] = dlt;
	}

	public static void registerDLT(PcapDLT dlt, int id) {
		registerDLT(dlt.getValue(), id);
	}

	/**
	 * Registers a new resolver of any type, replacing the previous resolver.
	 * 
	 * @param customType
	 *          type of resolver to replace
	 * @param custom
	 *          new resolver to register
	 */
	public static void registerResolver(Object customType, Resolver custom) {
		resolvers.put(customType, custom);
	}

	/**
	 * Registers a new resolver of specific type, replacing the previous resolver.
	 * 
	 * @param type
	 *          type of resolver to replace
	 * @param custom
	 *          new resolver to register
	 */
	public static void registerResolver(ResolverType type, Resolver custom) {
		resolvers.put(type, custom);
	}

	/**
	 * Clears any existing java bindings for the specified protocol
	 * 
	 * @param id
	 *          numerical id of the protocol header
	 */
	public static void resetBindings(int id) {
		scanners[id].clearBindings();
	}

	/**
	 * Sets the current flag for a specified protocol
	 * 
	 * @param id
	 *          numerical id of the protocol header
	 * @param flags
	 *          flags to set (bitwise OR) with the existing flags
	 */
	public static void setFlags(int id, int flags) {
		headerFlags[id] |= flags;
	}

	public static void setScanners(AnnotatedScannerMethod... scanners) {
		for (AnnotatedScannerMethod m : scanners) {
			JHeaderScanner scanner = JRegistry.scanners[m.getId()];

			scanner.setScannerMethod(m);
		}
	}

	public static void setScanners(Class<?> c) {
		if (JHeader.class.isAssignableFrom(c)) {
			setScanners(AnnotatedScannerMethod
			    .inspectJHeaderClass((Class<? extends JHeader>) c));
		} else {
			setScanners(AnnotatedScannerMethod
			    .inspectClass((Class<? extends JHeader>) c));
		}
	}

	/**
	 * @param container
	 */
	public static void setScanners(Object container) {
		AnnotatedScannerMethod[] methods =
		    AnnotatedScannerMethod.inspectObject(container);

		setScanners(methods);
	}

	/**
	 * Dumps various tables JRegistry maintains as debug information.
	 * 
	 * @return multi-line string containing various debug information about
	 *         JRegistry
	 */
	public static String toDebugString() {
		Formatter out = new Formatter();

		try {
			/*
			 * Dump scanners and their configs
			 */
			for (int i = 0; i < A_MAX_ID_COUNT; i++) {
				if (scanners[i] != null) {
					out.format("scanner[%-2d] class=%-15s %s\n", i, lookupClass(i)
					    .getSimpleName(), scanners[i].toString());
				}
			}

			/*
			 * Dump existing DLT to ID mappings
			 */
			for (int i = 0; i < MAX_DLT_COUNT; i++) {
				if (hasDltMapping(i)) {
					int id = mapDLTToId(i);
					Class<?> c = lookupClass(id);

					out.format("libpcap::%-24s => header::%s.class(%d)\n", PcapDLT
					    .valueOf(i).toString()
					    + "(" + i + ")", c.getSimpleName(), id);
				}
			}
		} catch (UnregisteredHeaderException e) {
			throw new IllegalStateException(e);
		}

		for (Object k : resolvers.keySet()) {
			Resolver r = resolvers.get(k);
			out.format("Resolver %s: %s\n", String.valueOf(k), r.toString());
		}

		return out.toString();
	}

	private JRegistry() {
		// Can't instantiate
	}

}