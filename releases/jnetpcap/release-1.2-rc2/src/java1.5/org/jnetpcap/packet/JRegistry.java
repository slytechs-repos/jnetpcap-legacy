package org.jnetpcap.packet;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
public class JRegistry {

	private static class Entry {
		public Class<? extends JHeader> clazz;

		public int id;

		public ThreadLocal<? extends JHeader> local;

		/**
		 * @param id
		 * @param c
		 */
		public Entry(int id, Class<? extends JHeader> c) {
			this.id = id;
			this.clazz = c;
		}
	}

	/**
	 * Maximum number of protocol header entries allowed by this implementation of
	 * JRegistry
	 */
	public final static int MAX_ID_COUNT = 64;

	/**
	 * This registries java bindings per each header
	 */
	private final static JBinding[][] bindings = new JBinding[MAX_ID_COUNT][];

	/**
	 * Number of core protocols defined by jNetPcap
	 */
	@SuppressWarnings("unused")
	public static final int CORE_ID_COUNT = JProtocol.values().length;

	/**
	 * Header scanners for each header type and protocol. The user can override
	 * native direct scanners by supplying a java based scanner that will override
	 * a particular protocols entry.
	 */
	private final static JHeaderScanner[] headerScanners =
	    new JHeaderScanner[MAX_ID_COUNT];

	/**
	 * A flag that allows tells that a java scanner's get length method has been
	 * overriden
	 */
	public final static int FLAG_OVERRIDE_LENGTH = 0x00000001;

	/**
	 * A flag that allows tells that a java scanner's process bindings method has
	 * been overriden
	 */
	public final static int FLAG_OVERRIDE_BINDING = 0x00000002;

	private final static int headerFlags[] = new int[MAX_ID_COUNT];

	private static int LAST_ID = 0;

	private final static Entry[] MAP_BY_ID = new Entry[MAX_ID_COUNT];

	/**
	 * Holds class to ID mapping - this is global accross all registries
	 */
	private static Map<Class<? extends JHeader>, Entry> mapByClass =
	    new HashMap<Class<? extends JHeader>, Entry>();

	/**
	 * Register all the core protocols as soon as the jRegistry class is loaded
	 */
	static {
		for (JProtocol p : JProtocol.values()) {
			register(p);
		}
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
	 * Adds additional bindings to a particular protocol
	 * 
	 * @param id
	 * @param bindings
	 */
	public static void addBinding(int id, JBinding... bindings) {

		final int l =
		    (JRegistry.bindings[id] != null) ? JRegistry.bindings[id].length : 0;
		List<JBinding> lb = new ArrayList<JBinding>(l + bindings.length);
		if (l != 0) {
			lb.addAll(Arrays.asList(bindings[id]));
		}
		lb.addAll(Arrays.asList(bindings));

		JRegistry.bindings[id] = lb.toArray(new JBinding[lb.size()]);
	}

	/**
	 * Retrieves all current bindings bound to a protocol
	 * 
	 * @param id
	 * @return
	 */
	public static JBinding[] getBindings(int id) {
		if (bindings[id] == null) {
			bindings[id] = new JBinding[0];
		}

		return bindings[id];
	}

	/**
	 * Looks up the class of a header based on its ID.
	 * 
	 * @param id
	 * @return
	 * @throws UnregisteredHeaderException
	 */
	public static Class<? extends JHeader> lookupClass(int id)
	    throws UnregisteredHeaderException {
		final Entry entry = MAP_BY_ID[id];
		if (entry == null) {
			throw new UnregisteredHeaderException("Header not registered: " + id);
		}

		return entry.clazz;
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
	public static int lookupId(Class<? extends JHeader> c)
	    throws UnregisteredHeaderException {
		Entry e = mapByClass.get(c);
		if (e == null) {
			throw new UnregisteredHeaderException();
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
		try {
			return lookupId(p.clazz);
		} catch (UnregisteredHeaderException e) {
			throw new IllegalStateException(e); // Internal error
		}
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
	 */
	public static <T extends JHeader> int register(Class<T> c,
	    JHeaderScanner scan, JBinding... bindings) {
		int id = LAST_ID++;
		Entry e = mapByClass.put(c, new Entry(id, c));
		MAP_BY_ID[id] = e;

		headerScanners[id] = scan;
		addBinding(id, bindings);

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
		Entry e = new Entry(protocol.ID, protocol.clazz);
		mapByClass.put(protocol.clazz, e);
		MAP_BY_ID[protocol.ID] = e;

		headerScanners[protocol.ID] = protocol.scan;

		return protocol.ID;
	}

	/**
	 * Clears any existing java bindings for the specified protocol
	 * 
	 * @param id
	 *          numerical id of the protocol header
	 */
	public static void resetBindings(int id) {
		bindings[id] = new JBinding[0];
	}

	/**
	 * Retrieves the entire list of scanners for all registered protocols
	 * 
	 * @return array of header scanners
	 */
	public static JHeaderScanner[] getHeaderScanners() {
		return headerScanners;
	}
}