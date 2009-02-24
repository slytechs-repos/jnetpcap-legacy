package org.jnetpcap.packet;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Formatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jnetpcap.PcapDLT;
import org.jnetpcap.analysis.JAnalyzer;
import org.jnetpcap.analysis.JController;
import org.jnetpcap.analysis.tcpip.Ip4Sequencer;
import org.jnetpcap.analysis.tcpip.Ip4Assembler;
import org.jnetpcap.analysis.tcpip.TcpAnalyzer;
import org.jnetpcap.analysis.tcpip.TcpSequencer;
import org.jnetpcap.analysis.tcpip.TcpAssembler;
import org.jnetpcap.analysis.tcpip.http.HttpAnalyzer;
import org.jnetpcap.packet.structure.AnnotatedBinding;
import org.jnetpcap.packet.structure.AnnotatedHeader;
import org.jnetpcap.packet.structure.AnnotatedScannerMethod;
import org.jnetpcap.packet.structure.HeaderDefinitionError;
import org.jnetpcap.util.resolver.Resolver;
import org.jnetpcap.util.resolver.Resolver.ResolverType;

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
		
		analyzers = new HashMap<Class<?>, JAnalyzer>();

		/**
		 * Register core analyzer: JController
		 */
		addAnalyzer(new JController());
		addAnalyzer(new Ip4Sequencer());
		addAnalyzer(new Ip4Assembler());
		addAnalyzer(new TcpAnalyzer());
		addAnalyzer(new TcpSequencer());
		addAnalyzer(new TcpAssembler());
		addAnalyzer(new HttpAnalyzer());
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

	private final static Map<Class<?>, JAnalyzer> analyzers;

	public static <T extends JAnalyzer> T getAnalyzer(Class<T> c) {
		return (T) analyzers.get(c);
	}

	public static <T extends JAnalyzer> void addAnalyzer(T analyzer) {
		analyzers.put(analyzer.getClass(), analyzer);
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
	 * Prepares the registry for shutdown. The registry will save caches and
	 * release resources other that may be held.
	 * 
	 * @throws IOException
	 */
	public static void shutdown() throws IOException {
		for (Resolver resolver : resolvers.values()) {
			if (resolver != null) {
				resolver.saveCache();
			}
		}

		resolvers.clear();
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
			r.initializeIfNeeded();
			out.format("Resolver %s: %s\n", String.valueOf(k), r.toString());
		}

		return out.toString();
	}

	private JRegistry() {
		// Can't instantiate
	}
}