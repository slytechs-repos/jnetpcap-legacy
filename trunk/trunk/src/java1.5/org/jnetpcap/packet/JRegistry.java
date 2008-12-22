package org.jnetpcap.packet;

import java.util.ArrayList;
import java.util.Formatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

	private static int LAST_ID = JProtocol.values().length;

	private final static Entry[] MAP_BY_ID = new Entry[A_MAX_ID_COUNT];

	/**
	 * Holds class to ID mapping - this is global accross all registries
	 */
	private static Map<String, Entry> mapByClassName =
	    new HashMap<String, Entry>();

	private static Map<String, AnnotatedHeader> mapSubsByClassName =
	    new HashMap<String, AnnotatedHeader>(50);

	/**
	 * Maximum number of protocol header entries allowed by this implementation of
	 * JRegistry
	 */
	public final static int MAX_ID_COUNT = 64;

	/**
	 * Header scanners for each header type and protocol. The user can override
	 * native direct scanners by supplying a java based scanner that will override
	 * a particular protocols entry.
	 */
	private final static JHeaderScanner[] scanners =
	    new JHeaderScanner[A_MAX_ID_COUNT];

	/**
	 * Register all the core protocols as soon as the jRegistry class is loaded
	 */
	static {
		for (JProtocol p : JProtocol.values()) {

			try {
				register(p);
			} catch (Exception e) {
				System.err.println("JRegistry Error: " + e.getMessage());
				e.printStackTrace();

				System.exit(0);
			}

		}
	}

	public static void addBindings(Class<?> c) {
		clearErrors();

		if (JHeader.class.isAssignableFrom(c)) {
			addBindings(AnnotatedBinding.inspectJHeaderClass(
			    (Class<? extends JHeader>) c, errors));

		} else {
			addBindings(AnnotatedBinding.inspectClass(c, errors));
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

	public static void addBindings(Object bindingContainer) {
		clearErrors();
		addBindings(AnnotatedBinding.inspectObject(bindingContainer, errors));
	}

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

	public static void clearScanners(Class<? extends JHeader>... classes) {
		for (Class<? extends JHeader> c : classes) {
			int id = lookupId(c);

			scanners[id].setScannerMethod(null);
		}
	}

	public static void clearScanners(int... ids) {
		for (int id : ids) {
			scanners[id].setScannerMethod(null);
		}
	}

	public static void clearScanners(Object container) {
		AnnotatedScannerMethod[] methods =
		    AnnotatedScannerMethod.inspectObject(container);

		int[] ids = new int[methods.length];

		for (int i = 0; i < ids.length; i++) {
			ids[i] = methods[i].getId();
		}

		clearScanners(ids);
	}

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

	public static boolean hasErrors() {
		return errors.isEmpty();
	}

	public static AnnotatedHeader inspect(
	    Class<? extends JHeader> c,
	    List<HeaderDefinitionError> errors) {

		return AnnotatedHeader.inspectJHeaderClass(c, errors);
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
		Entry e = MAP_BY_ID[protocol.ID];

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

		return (entry == null) ? null : entry.getHeaderClass();
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
		return p.ID;
	}

	private static int lookupIdNoCreate(Class<? extends JHeader> c)
	    throws UnregisteredHeaderException {
		if (mapByClassName.containsKey(c.getCanonicalName()) == false) {
			throw new UnregisteredHeaderException("header [" + c.getName()
			    + "] not registered");
		}

		return mapByClassName.get(c.getCanonicalName()).id;
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

		Entry e = new Entry(protocol.ID, protocol.getHeaderClassName());
		mapByClassName.put(protocol.getHeaderClassName(), e);
		MAP_BY_ID[protocol.ID] = e;

		scanners[protocol.ID] = new JHeaderScanner(protocol);

		return protocol.ID;
	}

	private static void registerAnnotatedSubHeaders(AnnotatedHeader[] subs) {
		for (AnnotatedHeader c : subs) {
			mapSubsByClassName.put(c.getHeaderClass().getCanonicalName(), c);

			registerAnnotatedSubHeaders(c.getHeaders());
		}
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
			setScanners(AnnotatedScannerMethod.inspectClass(c));
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

	public static String toDebugString() {
		Formatter out = new Formatter();

		try {
			for (int i = 0; i < A_MAX_ID_COUNT; i++) {
				if (scanners[i] != null) {
					out.format("scanner[%-2d] class=%-15s %s\n", i, lookupClass(i)
					    .getSimpleName(), scanners[i].toString());
				}
			}
		} catch (UnregisteredHeaderException e) {
			throw new IllegalStateException(e);
		}

		return out.toString();
	}

	private JRegistry() {
		// Can't instantiate
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

}