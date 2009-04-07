package org.jnetpcap.packet;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A scanner jRegistry
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

	public final static int MAX_ID_COUNT = 64;

	/**
	 * This registries java bindings per each header
	 */
	private final static JBinding[][] bindings = new JBinding[MAX_ID_COUNT][];

	@SuppressWarnings("unused")
	public static final int CORE_ID_COUNT = JProtocol.values().length;

	/**
	 * Header scanners for each header type and protocol. The user can override
	 * native direct scanners by supplying a java based scanner that will override
	 * a particular protocols entry.
	 */
	private final static JHeaderScanner[] headerScanners =
	    new JHeaderScanner[MAX_ID_COUNT];

	public final static int FLAG_OVERRIDE_LENGTH = 0x00000001;

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

	public static int getFlags(int id) {
		return headerFlags[id];
	}

	public static void setFlags(int id, int flags) {
		headerFlags[id] |= flags;
	}

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
		List<JBinding> lb =
		    new ArrayList<JBinding>(l + bindings.length);
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
	 * @param p
	 * @return
	 * @throws UnregisteredHeaderException
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
	 * @param p
	 * @return
	 * @throws UnregisteredHeaderException
	 */
	public static int lookupId(JProtocol p) throws UnregisteredHeaderException {
		return lookupId(p.clazz);
	}

	public static <T extends JHeader> int register(Class<T> c,
	    JHeaderScanner scan, JBinding... bindings) {
		int id = LAST_ID++;
		Entry e = mapByClass.put(c, new Entry(id, c));
		MAP_BY_ID[id] = e;

		headerScanners[id] = scan;
		addBinding(id, bindings);

		return id;
	}

	static int register(JProtocol protocol) {
		Entry e = new Entry(protocol.ID, protocol.clazz);
		mapByClass.put(protocol.clazz, e);
		MAP_BY_ID[protocol.ID] = e;

		headerScanners[protocol.ID] = protocol.scan;

		return protocol.ID;
	}

	public static void resetBindings(int id) {
		bindings[id] = new JBinding[0];
	}

	/**
   * @return
   */
  public static JHeaderScanner[] getHeaderScanners() {
	  return headerScanners;
  }
}