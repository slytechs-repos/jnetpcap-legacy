/*
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010 Sly Technologies, Inc.
 *
 * This file is part of jNetPcap.
 *
 * jNetPcap is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as 
 * published by the Free Software Foundation, either version 3 of 
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.jnetpcap.packet;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Formatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jnetpcap.PcapDLT;
import org.jnetpcap.packet.structure.AnnotatedBinding;
import org.jnetpcap.packet.structure.AnnotatedHeader;
import org.jnetpcap.packet.structure.AnnotatedScannerMethod;
import org.jnetpcap.packet.structure.HeaderDefinitionError;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.util.resolver.Resolver;
import org.jnetpcap.util.resolver.Resolver.ResolverType;

// TODO: Auto-generated Javadoc
/**
 * The Class JRegistry.
 */
@SuppressWarnings("unchecked")
public final class JRegistry {

	/**
	 * The Class Entry.
	 */
	private static class Entry {
		
		/** The annotated header. */
		private AnnotatedHeader annotatedHeader;

		/** The class name. */
		private final String className;

		/** The clazz. */
		private Class<? extends JHeader> clazz;

		/** The id. */
		private final int id;

		/**
		 * Instantiates a new entry.
		 * 
		 * @param id
		 *          the id
		 * @param c
		 *          the c
		 */
		public Entry(int id, Class<? extends JHeader> c) {
			this.id = id;
			this.clazz = c;
			this.className = c.getName();
		}

		/**
		 * Instantiates a new entry.
		 * 
		 * @param id
		 *          the id
		 * @param className
		 *          the class name
		 */
		public Entry(int id, String className) {
			this.id = id;
			this.className = className;
		}

		/**
		 * Gets the header class.
		 * 
		 * @return the header class
		 */
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

	/** The Constant A_MAX_ID_COUNT. */
	private final static int A_MAX_ID_COUNT = 64;

	/** The Constant CORE_ID_COUNT. */
	public static final int CORE_ID_COUNT = JProtocol.values().length;

	/** The Constant DLTS_TO_IDS. */
	private final static int[] DLTS_TO_IDS;

	/** The errors. */
	private static List<HeaderDefinitionError> errors = new ArrayList<HeaderDefinitionError>();

	/** The Constant FLAG_HEURISTIC_BINDING. */
	public final static int FLAG_HEURISTIC_BINDING = 0x00000010;

	/** The Constant FLAG_HEURISTIC_PRE_BINDING. */
	public final static int FLAG_HEURISTIC_PRE_BINDING = 0x00000020;

	/** The Constant FLAG_OVERRIDE_BINDING. */
	public final static int FLAG_OVERRIDE_BINDING = 0x00000002;

	/** The Constant FLAG_OVERRIDE_LENGTH. */
	public final static int FLAG_OVERRIDE_LENGTH = 0x00000001;

	/** The Constant headerFlags. */
	private final static int headerFlags[] = new int[A_MAX_ID_COUNT];

	/** The Constant IDS_TO_DLTS. */
	private final static int[] IDS_TO_DLTS;

	/** The LAS t_ id. */
	private static int LAST_ID = JProtocol.values().length;

	/** The Constant MAP_BY_ID. */
	private final static Entry[] MAP_BY_ID = new Entry[A_MAX_ID_COUNT];

	/** The map by class name. */
	private static Map<String, Entry> mapByClassName = new HashMap<String, Entry>();

	/** The map subs by class name. */
	private static Map<String, AnnotatedHeader> mapSubsByClassName = new HashMap<String, AnnotatedHeader>(
			50);

	/** The Constant MAX_DLT_COUNT. */
	private static final int MAX_DLT_COUNT = 512;

	/** The Constant MAX_ID_COUNT. */
	public final static int MAX_ID_COUNT = 64;

	/** The Constant NO_DLT_MAPPING. */
	public static final int NO_DLT_MAPPING = -1;

	/** The Constant resolvers. */
	private final static Map<Object, Resolver> resolvers = new HashMap<Object, Resolver>();

	/** The Constant scanners. */
	private final static JHeaderScanner[] scanners = new JHeaderScanner[A_MAX_ID_COUNT];

	/**
	 * Initialize JRegistry with defaults
	 * <ul>
	 * <li>libpcap DLT mappings</li>
	 * <li>Register CORE protocols</li>
	 * <li>Register address resolvers</li>
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
		 * Bind CORE protocols. Most bindings are provided by the native scanner
		 * but some protocols may have java bindings as well that need to be
		 * registered. They are by default registered in addition to the native
		 * bindings.
		 */
		for (JProtocol p : JProtocol.values()) {

			try {
				JBinding[] bindings = AnnotatedBinding.inspectJHeaderClass(
						p.getHeaderClass(), errors);
				if (bindings != null && bindings.length != 0) {
					addBindings(bindings);
				}
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

		/**
		 * Enable heuristics by default for TCP and UDP protocols
		 */
		setFlags(JProtocol.TCP_ID, FLAG_HEURISTIC_BINDING);
		setFlags(JProtocol.UDP_ID, FLAG_HEURISTIC_BINDING);

	}

	/**
	 * Adds the bindings.
	 * 
	 * @param container
	 *          the container
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
	 * Adds the bindings.
	 * 
	 * @param bindings
	 *          the bindings
	 */
	public static void addBindings(JBinding... bindings) {

		for (JBinding b : bindings) {
			scanners[b.getTargetId()].addBindings(b);
		}

	}

	/**
	 * Adds the bindings.
	 * 
	 * @param bindingContainer
	 *          the binding container
	 */
	public static void addBindings(Object bindingContainer) {
		if (bindingContainer instanceof JBinding) {
			addBindings(new JBinding[] { (JBinding) bindingContainer });
			return;
		}

		clearErrors();
		addBindings(AnnotatedBinding.inspectObject(bindingContainer, errors));
	}

	/**
	 * Clear errors.
	 */
	public static void clearErrors() {
		errors.clear();
	}

	/**
	 * Clear flags.
	 * 
	 * @param id
	 *          the id
	 * @param flags
	 *          the flags
	 */
	public static void clearFlags(int id, int flags) {
		headerFlags[id] &= ~flags;
	}

	/**
	 * Clear scanners.
	 * 
	 * @param classes
	 *          the classes
	 */
	public static void clearScanners(Class<? extends JHeader>... classes) {
		for (Class<? extends JHeader> c : classes) {
			int id = lookupId(c);

			scanners[id].setScannerMethod(null);
		}
	}

	/**
	 * Clear scanners.
	 * 
	 * @param ids
	 *          the ids
	 */
	public static void clearScanners(int... ids) {
		for (int id : ids) {
			scanners[id].setScannerMethod(null);
		}
	}

	/**
	 * Clear scanners.
	 * 
	 * @param container
	 *          the container
	 */
	public static void clearScanners(Object container) {
		AnnotatedScannerMethod[] methods = AnnotatedScannerMethod
				.inspectObject(container);

		int[] ids = new int[methods.length];

		for (int i = 0; i < ids.length; i++) {
			ids[i] = methods[i].getId();
		}

		clearScanners(ids);
	}

	/**
	 * Creates the new entry.
	 * 
	 * @param c
	 *          the c
	 * @return the entry
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
	 * Gets the bindings.
	 * 
	 * @param id
	 *          the id
	 * @return the bindings
	 */
	public static JBinding[] getBindings(int id) {
		return scanners[id].getBindings();
	}

	/**
	 * Gets the errors.
	 * 
	 * @return the errors
	 */
	public static HeaderDefinitionError[] getErrors() {
		return errors.toArray(new HeaderDefinitionError[errors.size()]);
	}

	/**
	 * Gets the flags.
	 * 
	 * @param id
	 *          the id
	 * @return the flags
	 */
	public static int getFlags(int id) {
		return headerFlags[id];
	}

	/**
	 * Gets the all flags.
	 * 
	 * @return the all flags
	 */
	public static int[] getAllFlags() {
		final int[] copy = new int[headerFlags.length];
		System.arraycopy(headerFlags, 0, copy, 0, copy.length);
		return copy;
	}

	/**
	 * Sets the all flags.
	 * 
	 * @param flags
	 *          the new all flags
	 */
	public static void setAllFlags(int[] flags) {
		System.arraycopy(flags, 0, headerFlags, 0, flags.length);
	}

	/**
	 * Gets the header scanners.
	 * 
	 * @return the header scanners
	 */
	public static JHeaderScanner[] getHeaderScanners() {
		JHeaderScanner[] s = new JHeaderScanner[MAX_ID_COUNT];
		System.arraycopy(scanners, 0, s, 0, MAX_ID_COUNT);

		return s;
	}

	/**
	 * Gets the resolver.
	 * 
	 * @param customType
	 *          the custom type
	 * @return the resolver
	 */
	public static Resolver getResolver(Object customType) {
		Resolver resolver = resolvers.get(customType);

		resolver.initializeIfNeeded();

		return resolver;
	}

	/**
	 * Gets the resolver.
	 * 
	 * @param type
	 *          the type
	 * @return the resolver
	 */
	public static Resolver getResolver(ResolverType type) {
		return getResolver((Object) type);
	}

	/**
	 * Checks for dlt mapping.
	 * 
	 * @param dlt
	 *          the dlt
	 * @return true, if successful
	 */
	public static boolean hasDltMapping(int dlt) {
		return dlt >= 0 && dlt < DLTS_TO_IDS.length
				&& DLTS_TO_IDS[dlt] != NO_DLT_MAPPING;
	}

	/**
	 * Checks for errors.
	 * 
	 * @return true, if successful
	 */
	public static boolean hasErrors() {
		return errors.isEmpty();
	}

	/**
	 * Checks for resolver.
	 * 
	 * @param type
	 *          the type
	 * @return true, if successful
	 */
	public static boolean hasResolver(Object type) {
		return resolvers.containsKey(type);
	}

	/**
	 * Checks for resolver.
	 * 
	 * @param type
	 *          the type
	 * @return true, if successful
	 */
	public static boolean hasResolver(ResolverType type) {
		return resolvers.containsKey(type);
	}

	/**
	 * Inspect.
	 * 
	 * @param c
	 *          the c
	 * @param errors
	 *          the errors
	 * @return the annotated header
	 */
	public static AnnotatedHeader inspect(Class<? extends JHeader> c,
			List<HeaderDefinitionError> errors) {

		return AnnotatedHeader.inspectJHeaderClass(c, errors);
	}

	/**
	 * List resolvers.
	 * 
	 * @return the object[]
	 */
	public static Object[] listResolvers() {
		return resolvers.keySet().toArray(new Object[resolvers.size()]);
	}

	/**
	 * Lookup annotated header.
	 * 
	 * @param c
	 *          the c
	 * @return the annotated header
	 * @throws UnregisteredHeaderException
	 *           the unregistered header exception
	 */
	public static AnnotatedHeader lookupAnnotatedHeader(
			Class<? extends JHeader> c) throws UnregisteredHeaderException {

		if (JSubHeader.class.isAssignableFrom(c)) {
			return lookupAnnotatedSubHeader((Class<? extends JSubHeader<? extends JSubHeader<?>>>) c);
		}

		return lookupAnnotatedHeader(lookupIdNoCreate(c));
	}

	/**
	 * Lookup annotated header.
	 * 
	 * @param id
	 *          the id
	 * @return the annotated header
	 * @throws UnregisteredHeaderException
	 *           the unregistered header exception
	 */
	public static AnnotatedHeader lookupAnnotatedHeader(int id)
			throws UnregisteredHeaderException {
		if (MAP_BY_ID[id] == null || MAP_BY_ID[id].annotatedHeader == null) {
			throw new UnregisteredHeaderException("header [" + id
					+ "] not registered");
		}

		return MAP_BY_ID[id].annotatedHeader;
	}

	/**
	 * Lookup annotated header.
	 * 
	 * @param protocol
	 *          the protocol
	 * @return the annotated header
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

	/**
	 * Lookup annotated sub header.
	 * 
	 * @param c
	 *          the c
	 * @return the annotated header
	 */
	static AnnotatedHeader lookupAnnotatedSubHeader(
			Class<? extends JSubHeader<? extends JSubHeader<?>>> c) {
		if (mapSubsByClassName.containsKey(c.getCanonicalName()) == false) {
			throw new UnregisteredHeaderException(
					"sub header ["
							+ c.getName()
							+ "] not registered, most likely parent not registered as well");
		}

		return mapSubsByClassName.get(c.getCanonicalName());
	}

	/**
	 * Lookup class.
	 * 
	 * @param id
	 *          the id
	 * @return the class<? extends j header>
	 * @throws UnregisteredHeaderException
	 *           the unregistered header exception
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
	 * Lookup id.
	 * 
	 * @param c
	 *          the c
	 * @return the int
	 */
	public static int lookupId(Class<? extends JHeader> c) {

		if (JSubHeader.class.isAssignableFrom(c)) {
			AnnotatedHeader header = lookupAnnotatedSubHeader((Class<? extends JSubHeader<? extends JSubHeader<?>>>) c);

			return header.getId();
		}

		Entry e = mapByClassName.get(c.getCanonicalName());
		if (e == null) {
			e = createNewEntry(c);
		}

		return e.id;
	}

	/**
	 * Lookup id.
	 * 
	 * @param p
	 *          the p
	 * @return the int
	 */
	public static int lookupId(JProtocol p) {
		return p.getId();
	}

	/**
	 * Lookup id no create.
	 * 
	 * @param c
	 *          the c
	 * @return the int
	 * @throws UnregisteredHeaderException
	 *           the unregistered header exception
	 */
	private static int lookupIdNoCreate(Class<? extends JHeader> c)
			throws UnregisteredHeaderException {
		if (mapByClassName.containsKey(c.getCanonicalName()) == false) {
			throw new UnregisteredHeaderException("header [" + c.getName()
					+ "] not registered");
		}

		return mapByClassName.get(c.getCanonicalName()).id;
	}

	/**
	 * Lookup scanner.
	 * 
	 * @param id
	 *          the id
	 * @return the j header scanner
	 */
	public static JHeaderScanner lookupScanner(int id) {
		return scanners[id];
	}

	/**
	 * Map dlt to id.
	 * 
	 * @param dlt
	 *          the dlt
	 * @return the int
	 */
	public static int mapDLTToId(int dlt) {
		return DLTS_TO_IDS[dlt];
	}

	/**
	 * Map id to dlt.
	 * 
	 * @param id
	 *          the id
	 * @return the int
	 */
	public static int mapIdToDLT(int id) {
		return IDS_TO_DLTS[id];
	}

	/**
	 * Map id to pcap dlt.
	 * 
	 * @param id
	 *          the id
	 * @return the pcap dlt
	 */
	public static PcapDLT mapIdToPcapDLT(int id) {
		return PcapDLT.valueOf(IDS_TO_DLTS[id]);
	}

	/**
	 * Register.
	 * 
	 * @param c
	 *          the c
	 * @return the int
	 * @throws RegistryHeaderErrors
	 *           the registry header errors
	 */
	public static int register(Class<? extends JHeader> c)
			throws RegistryHeaderErrors {

		List<HeaderDefinitionError> errors = new ArrayList<HeaderDefinitionError>();

		int id = register(c, errors);

		if (errors.isEmpty() == false) {
			throw new RegistryHeaderErrors(c, errors,
					"while trying to register " + c.getSimpleName() + " class");
		}

		return id;
	}

	/**
	 * Register.
	 * 
	 * @param c
	 *          the c
	 * @param errors
	 *          the errors
	 * @return the int
	 */
	public static int register(Class<? extends JHeader> c,
			List<HeaderDefinitionError> errors) {

		AnnotatedHeader annotatedHeader = inspect(c, errors);
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

		JBinding[] bindings = AnnotatedBinding.inspectJHeaderClass(c, errors);
		if (errors.isEmpty() == false) {
			return -1;
		}
		addBindings(bindings);

		for (PcapDLT d : annotatedHeader.getDlt()) {
			registerDLT(d, id);
		}

		return id;
	}

	/**
	 * Register.
	 * 
	 * @param protocol
	 *          the protocol
	 * @return the int
	 */
	static int register(JProtocol protocol) {

		Entry e = new Entry(protocol.getId(), protocol.getHeaderClassName());
		mapByClassName.put(protocol.getHeaderClassName(), e);
		MAP_BY_ID[protocol.getId()] = e;

		try {
			scanners[protocol.getId()] = new JHeaderScanner(protocol);
		} catch (UnregisteredHeaderException ex) {
			register(protocol.getClazz(), errors);
		}

		for (PcapDLT d : protocol.getDlt()) {
			registerDLT(d, protocol.getId());
		}

		return protocol.getId();
	}

	/**
	 * Register annotated sub headers.
	 * 
	 * @param subs
	 *          the subs
	 */
	private static void registerAnnotatedSubHeaders(AnnotatedHeader[] subs) {
		for (AnnotatedHeader c : subs) {
			mapSubsByClassName.put(c.getHeaderClass().getCanonicalName(), c);

			registerAnnotatedSubHeaders(c.getHeaders());
		}
	}

	/**
	 * Register dlt.
	 * 
	 * @param dlt
	 *          the dlt
	 * @param id
	 *          the id
	 */
	public static void registerDLT(int dlt, int id) {
		DLTS_TO_IDS[dlt] = id;
		IDS_TO_DLTS[id] = dlt;
	}

	/**
	 * Register dlt.
	 * 
	 * @param dlt
	 *          the dlt
	 * @param id
	 *          the id
	 */
	public static void registerDLT(PcapDLT dlt, int id) {
		registerDLT(dlt.getValue(), id);
	}

	/**
	 * Register resolver.
	 * 
	 * @param customType
	 *          the custom type
	 * @param custom
	 *          the custom
	 */
	public static void registerResolver(Object customType, Resolver custom) {
		resolvers.put(customType, custom);
	}

	/**
	 * Register resolver.
	 * 
	 * @param type
	 *          the type
	 * @param custom
	 *          the custom
	 */
	public static void registerResolver(ResolverType type, Resolver custom) {
		resolvers.put(type, custom);
	}

	/**
	 * Reset bindings.
	 * 
	 * @param id
	 *          the id
	 */
	public static void resetBindings(int id) {
		scanners[id].clearBindings();
	}

	/**
	 * Sets the flags.
	 * 
	 * @param id
	 *          the id
	 * @param flags
	 *          the flags
	 */
	public static void setFlags(int id, int flags) {
		headerFlags[id] |= flags;
	}

	/**
	 * Sets the header scanners for each header type and protocol.
	 * 
	 * @param scanners
	 *          the new header scanners for each header type and protocol
	 */
	public static void setScanners(AnnotatedScannerMethod... scanners) {
		for (AnnotatedScannerMethod m : scanners) {
			JHeaderScanner scanner = JRegistry.scanners[m.getId()];

			scanner.setScannerMethod(m);
		}
	}

	/**
	 * Sets the header scanners for each header type and protocol.
	 * 
	 * @param c
	 *          the new header scanners for each header type and protocol
	 */
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
	 * Sets the header scanners for each header type and protocol.
	 * 
	 * @param container
	 *          the new header scanners for each header type and protocol
	 */
	public static void setScanners(Object container) {
		AnnotatedScannerMethod[] methods = AnnotatedScannerMethod
				.inspectObject(container);

		setScanners(methods);
	}

	/**
	 * Shutdown.
	 * 
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
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
	 * To debug string.
	 * 
	 * @return the string
	 */
	public static String toDebugString() {
		Formatter out = new Formatter();

		try {
			/*
			 * Dump scanners and their configs
			 */
			for (int i = 0; i < A_MAX_ID_COUNT; i++) {
				if (scanners[i] != null) {
					out.format("scanner[%-2d] class=%-15s %s\n", i,
							lookupClass(i).getSimpleName(),
							scanners[i].toString());
				}
			}

			/*
			 * Dump existing DLT to ID mappings
			 */
			for (int i = 0; i < MAX_DLT_COUNT; i++) {
				if (hasDltMapping(i)) {
					int id = mapDLTToId(i);
					Class<?> c = lookupClass(id);

					out.format("libpcap::%-24s => header::%s.class(%d)\n",
							PcapDLT.valueOf(i).toString() + "(" + i + ")",
							c.getSimpleName(), id);
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

	/**
	 * Instantiates a new j registry.
	 */
	private JRegistry() {
		// Can't instantiate
	}
}