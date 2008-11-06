package org.jnetpcap.packet;

import java.util.ArrayList;
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

		public ThreadLocal<? extends JHeader> threadLocal() {
			if (local == null) {
				local = new ThreadLocal<JHeader>() {
					@Override
					protected JHeader initialValue() {
						try {
							return clazz.newInstance();
						} catch (Exception e) {
							throw new IllegalStateException(e);
						}
					}
				};
			}

			return local;
		}
	}

	@SuppressWarnings("unused")
	private static final int CORE_ID_COUNT = JProtocol.values().length;

	private static JRegistry global = null;

	private static int LAST_ID = 0;

	/**
	 * Holds class to ID mapping - this is global accross all registries
	 */
	private static Map<Class<? extends JHeader>, Entry> mapByClass =
	    new HashMap<Class<? extends JHeader>, Entry>();

	public static final int MAX_ID_COUNT = 64;
	
	private static Entry[] mapById = new Entry[MAX_ID_COUNT];

	private static final int NULL_ID = -1;

	/**
	 * Register all the core protocols as soon as the jRegistry class is loaded
	 */
	static {
		for (JProtocol p : JProtocol.values()) {
			register(p);
		}
	}

	public static JRegistry getGlobal() {
		if (global == null) {
			global = new JRegistry();
		}

		return global;
	}

	public static <T extends JHeader> int register(Class<T> c) {
		int id = LAST_ID++;
		Entry e = mapByClass.put(c, new Entry(id, c));
		mapById[id] = e;

		return id;
	}

	public static <T extends JHeader> int register(Class<T> c,
	    JBinding... bindings) {
		int id = register(c);

		getGlobal().setBindings(bindings);

		return id;
	}

	static int register(JProtocol protocol) {
		Entry e = new Entry(protocol.ID, protocol.clazz);
		mapByClass.put(protocol.clazz, e);
		mapById[protocol.ID] = e;

		return protocol.ID;
	}

	private List<JBinding>[] bindingsBySource = new ArrayList[MAX_ID_COUNT];

	private List<JBinding>[] bindingsByTarget = new ArrayList[MAX_ID_COUNT];

	private int[][] overrides = new int[MAX_ID_COUNT][];

	protected final JBinding[][] getBindingsBySource() {
		return toArray(this.bindingsBySource);
	}

	protected final JBinding[][] getBindingsByTarget() {
		return toArray(this.bindingsByTarget);
	}

	public final int[][] getOverrides() {
		return this.overrides;
	}

	public int[] getOverrides(JProtocol protocol) {
		return this.overrides[protocol.ID];
	}

	/**
	 * @param id
	 * @return
	 * @throws UnregisteredHeaderException
	 */
	public Class<? extends JHeader> lookupClass(int id) throws UnregisteredHeaderException {
		final Entry entry = mapById[id];
		if (entry == null) {
			throw new UnregisteredHeaderException("Header not registered: " + id);
		}

		return entry.clazz;
	}

	/**
	 * @param p
	 * @return
	 */
	public int lookupId(Class<? extends JHeader> c) {
		Entry e = mapByClass.get(c);
		if (e == null) {
			return NULL_ID;
		}

		return e.id;
	}

	/**
	 * @param p
	 * @return
	 */
	public int lookupId(JProtocol p) {
		return lookupId(p.clazz);
	}

	/**
	 * @param bindings2
	 */
	public void setBindings(JBinding... bindings) {

		setSourceBindings(bindings);
		setTargetBindings(bindings);

	}

	/**
	 * Overrides allow a user to override binding on a CORE protocol that has been
	 * implemented using a native algorithm. Once a CORE binding has been
	 * overriden, a java binding must be supplied, otherwise the next header will
	 * never be matched. Without the override, CORE bindings once succeed, never
	 * check java bindings.
	 * 
	 * @param protocol
	 *          protocol to which override is to be applied
	 * @param overrides
	 *          a list of header IDs for which to apply override
	 */
	public void setOverrides(JProtocol protocol, int... overrides) {
		this.overrides[protocol.ID] = overrides;
	}

	private void setSourceBinding(int id, JBinding binding) {
		if (id < 0 || id > MAX_ID_COUNT) {
			throw new IndexOutOfBoundsException(
			    "Id is out of bounds. Currently only " + MAX_ID_COUNT
			        + " IDs are supported.");
		}
		List<JBinding> source = this.bindingsBySource[id];
		if (source == null) {
			source = new ArrayList<JBinding>();
			this.bindingsBySource[id] = source;
		}

		source.add(binding);
	}

	private void setSourceBindings(JBinding... bindings) {
		for (JBinding b : bindings) {
			setSourceBinding(b.getId(), b);
		}
	}

	private void setTargetBinding(int id, JBinding binding) {

		List<JBinding> target = this.bindingsByTarget[id];
		if (target == null) {
			target = new ArrayList<JBinding>();
			this.bindingsByTarget[id] = target;
		}

		target.add(binding);
	}

	private void setTargetBindings(JBinding... bindings) {
		for (JBinding b : bindings) {
			setTargetBinding(b.getTargetId(), b);
		}
	}

	@SuppressWarnings("unchecked")
	private JBinding[][] toArray(List<JBinding>[] bindings) {
		final JBinding[][] r = new JBinding[bindings.length][];

		for (int i = 0; i < r.length; i++) {
			final List<?> l = bindings[i];
			if (l == null) {
				r[i] = new JBinding[0];
			} else {
				r[i] = l.toArray(new JBinding[l.size()]);
			}
		}

		return r;
	}
}