/**
 * Copyright (C) 2008 Sly Technologies, Inc. This library is free software; you
 * can redistribute it and/or modify it under the terms of the GNU Lesser
 * General Public License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version. This
 * library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details. You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
package org.jnetpcap.packet;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JStruct;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.FieldRuntime;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.FieldRuntime.FieldFunction;
import org.jnetpcap.packet.format.JDynamicField;
import org.jnetpcap.packet.format.JField;
import org.jnetpcap.packet.format.JFieldRuntime;
import org.jnetpcap.packet.format.JFormatter.Priority;
import org.jnetpcap.packet.format.JFormatter.Style;

/**
 * A base class for all protocol header definitions.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class JHeader
    extends JBuffer {

	/**
	 * This class is peered state of a header a native state structure
	 * 
	 * <pre>
	 * typedef struct header_t {
	 * 	int32_t hdr_id; // header ID
	 * 	uint32_t hdr_offset; // offset into the packet_t-&gt;data buffer
	 * 	int32_t hdr_length; // length of the header in packet_t-&gt;data buffer
	 * } header_t;
	 * 
	 * </pre>
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class State
	    extends JStruct {

		public final static String STRUCT_NAME = "header_t";

		/**
		 * Create an uninitialized type
		 * 
		 * @param type
		 *          type of memory
		 */
		public State(Type type) {
			super(STRUCT_NAME, type);
		}

		public native int getId();

		public native int getLength();

		public native int getOffset();

		public boolean isDirect() {
			return true;
		}

		public int peer(State peer) {
			if (peer.isDirect() == false) {
				throw new IllegalStateException(
				    "DirectState can only peer with another DirectState");
			}
			return super.peer(peer);
		}

		public String toString() {
			return "(id=" + getId() + ", offset=" + getOffset() + ", length="
			    + getLength() + ")";
		}
	}

	/**
	 * Default field object for JFormatter that does a hex dump on the entire
	 * header
	 */
	public final static JField[] DEFAULT_FIELDS =
	    { new JField(Style.BYTE_ARRAY_HEX_DUMP, Priority.LOW, "data", "data",
	        new JDynamicField<JHeader, byte[]>(0) {

		        /*
						 * (non-Javadoc)
						 * 
						 * @see org.jnetpcap.packet.format.JDynamicField#hasField(org.jnetpcap.packet.JHeader)
						 */
		        @Override
		        public boolean hasField(JHeader header) {
			        setLength(header.getLength());
			        setOffset(header.getOffset());

			        return header.getLength() != 0;
		        }

		        public byte[] value(JHeader header) {
			        return header.getByteArray(0, header.getLength());
		        }
	        }), };

	protected final static JHeader[] EMPTY_HEADER_ARRAY = new JHeader[0];

	/**
	 * Gets the size of the native header_t structure on this particular platform
	 * 
	 * @return length in bytes
	 */
	public native static int sizeof();

	private JField[] fields;

	private int id;

	private Map<String, AnnotatedFieldRuntime> inspectedFieldRuntimes =
	    new HashMap<String, AnnotatedFieldRuntime>();

	private Map<String, AnnotatedField> inspectedFields =
	    new HashMap<String, AnnotatedField>();

	private Map<String, List<AnnotatedField>> inspectedSubFields =
	    new HashMap<String, List<AnnotatedField>>();

	private String name;

	private String nicname;

	/**
	 * A reference to the packet that this header is part of
	 */
	protected JPacket packet;

	/**
	 * Reference to header's native state structure
	 */
	protected final State state;

	protected boolean isSubHeader = false;

	public JHeader() {
		super(Type.POINTER);
		state = new State(Type.POINTER);
		
		if(!(this instanceof JHeaderMap)) {
			inspect();
		}

	}
	
	protected void inspect() {
		Class<? extends JHeader> c = getClass();

		inspectHeader(c);

		fields = inspectHeaderFields(c);
		setSubHeaders(inspectSubHeaders(c));

		if (!isSubHeader) {
			this.id = JRegistry.lookupId(c);
		}

	}

	public void setSubHeaders(JHeader[] headers) {
	}

	/**
	 * @param c
	 * @return
	 */
	@SuppressWarnings("unchecked")
	protected JHeader[] inspectSubHeaders(Class<? extends JHeader> c) {

		List<JHeader> list = new ArrayList<JHeader>();
		for (Class<?> s : c.getDeclaredClasses()) {
			Header header = s.getAnnotation(Header.class);
			if (header == null) {
				continue; // Doesn't @Header tag, not a real sub-header
			}

			try {
				Constructor<JHeader> constructor =
				    (Constructor<JHeader>) s.getConstructor();
				JHeader jheader = constructor.newInstance();
				jheader.id = header.value(); // Set sub-header's ID directly
				list.add(jheader);

			} catch (SecurityException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InstantiationException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalAccessException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchMethodException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalArgumentException e) {
	      // TODO Auto-generated catch block
	      e.printStackTrace();
      } catch (InvocationTargetException e) {
	      // TODO Auto-generated catch block
	      e.printStackTrace();
      }
		}

		return list.toArray(new JHeader[list.size()]);
	}

	/**
	 * Constructs a header and initializes its static fields
	 * 
	 * @param id
	 *          numerical ID of the protocol
	 * @param fields
	 *          fields usd by the formatter to reformat the packet for output
	 * @param name
	 *          comprehensive name of the protocol
	 */
	public JHeader(int id, JField[] fields, String name) {
		this(id, fields, name, name);
	}

	/**
	 * Constructs a header and initializes its static fields
	 * 
	 * @param id
	 *          numerical ID of the protocol
	 * @param fields
	 *          fields usd by the formatter to reformat the packet for output
	 * @param name
	 *          comprehensive name of the protocol
	 * @param nicname
	 *          a short name for the protocol
	 */
	public JHeader(int id, JField[] fields, String name, String nicname) {
		super(Type.POINTER);
		this.fields = fields;

		this.id = id;
		this.name = name;
		this.nicname = nicname;
		this.state = new State(Type.POINTER);
		super.order(ByteOrder.nativeOrder());

	}

	/**
	 * Constructs a header.
	 * 
	 * @param id
	 *          numerical ID of the protocol
	 * @param name
	 *          comprehensive name of the protocol
	 */
	public JHeader(int id, String name) {
		this(id, name, name);
	}

	/**
	 * Constructs a header.
	 * 
	 * @param id
	 *          numerical ID of the protocol
	 * @param name
	 *          comprehensive name of the protocol
	 * @param nicname
	 *          a short name for the protocol
	 */
	public JHeader(int id, String name, String nicname) {
		this(id, DEFAULT_FIELDS, name, nicname);
	}

	/**
	 * Constructs a header and initializes its static fields
	 * 
	 * @param state
	 *          the default header state object being referenced
	 * @param fields
	 *          fields usd by the formatter to reformat the packet for output
	 * @param name
	 *          comprehensive name of the protocol
	 * @param nicname
	 *          a short name for the protocol
	 */
	public JHeader(State state, JField[] fields, String name, String nicname) {
		super(Type.POINTER);

		this.state = state;
		this.fields = fields;
		this.name = name;
		this.nicname = nicname;
		this.id = state.getId();
		super.order(ByteOrder.nativeOrder());
	}

	/**
	 * Method that gets called everytime a header is successfully peered with new
	 * buffer and/or state structure. This method in JHeader is empty and is
	 * expected to be overriden by subclasses of JHeader that require special
	 * processing of the header such as decoding its structure at runtime when the
	 * header object is bound to new state.
	 */
	public final void decode() {
		decodeHeader();
		validateHeader();
	}

	/**
	 * Allows a header to decode its complex fields
	 */
	protected void decodeHeader() {

	}

	/**
	 * Retrieves the fields at runtime, that this header has so that they may be
	 * used by a formatter
	 * 
	 * @return an array of fields that this header is made up of, as determined at
	 *         runtime
	 */
	public JField[] getFields() {

		final JHeader header = this;

		Arrays.sort(fields, new Comparator<JField>() {

			@SuppressWarnings("unchecked")
			public int compare(JField o1, JField o2) {
				final JFieldRuntime<JHeader, Object> r1 =
				    (JFieldRuntime<JHeader, Object>) o1.getRuntime();
				final JFieldRuntime<JHeader, Object> r2 =
				    (JFieldRuntime<JHeader, Object>) o2.getRuntime();

				return r1.getOffset(header) - r2.getOffset(header);
			}

		});

		return this.fields;
	}

	/**
	 * Gets the numerical ID of this protocol header at runtime as assigned by the
	 * JRegistry
	 * 
	 * @return unique numerical ID of this header
	 */
	public final int getId() {
		return this.id;
	}

	/**
	 * Length of this header within the buffer
	 * 
	 * @return length in bytes
	 */
	public int getLength() {
		return this.state.getLength();
	}

	/**
	 * Gets the comprehensive name for this header
	 * 
	 * @return the name full name of this header
	 */
	public final String getName() {
		return this.name;
	}

	/**
	 * Gets the short name for this header
	 * 
	 * @return the nicname for this header
	 */
	public final String getNicname() {
		return this.nicname;
	}

	/**
	 * Offset into the packet buffer
	 * 
	 * @return offset into the buffer in bytes
	 */
	public int getOffset() {
		return state.getOffset();
	}

	/**
	 * Gets the packet that this header is associated with
	 * 
	 * @return parent packet
	 */
	public final JPacket getPacket() {
		return this.packet;
	}

	public JHeader getParent() {
		return this;
	}

	/**
	 * Gets the reference to the current header's native state structure
	 * 
	 * @return current state of the header
	 */
	public State getState() {
		return state;
	}

	/**
	 * Gets an array of currently defined sub headers
	 * 
	 * @return array of sub headers
	 */
	public JHeader[] getSubHeaders() {
		return EMPTY_HEADER_ARRAY;
	}

	/**
	 * @param name
	 * @return
	 */
	private String guessFieldName(String name) {
		if (name.endsWith("Description")) {
			return name.replace("Description", "");
		} else if (name.endsWith("Offset")) {
			return name.replace("Offset", "");
		} else if (name.endsWith("Length")) {
			return name.replace("Length", "");
		} else if (name.endsWith("Mask")) {
			return name.replace("Mask", "");
		} else if (name.endsWith("Value")) {
			return name.replace("Value", "");
		} else if (name.startsWith("has")) {
			String cap = name.replace("Value", "");
			char u = cap.charAt(0);
			char l = Character.toLowerCase(u);
			return cap.replace(u, l);
		} else {
			return name;
		}
	}

	public boolean hasSubHeaders() {
		return false;
	}

	/**
	 * @param c
	 * @param method
	 * @return
	 */
	private AnnotatedFieldRuntime inspectDynamicFieldMethod(
	    Class<? extends JHeader> c,
	    Method method) {
		FieldRuntime annotation = method.getAnnotation(FieldRuntime.class);

		String name = method.getName();
		String fieldName =
		    (annotation.field().isEmpty()) ? guessFieldName(name) : annotation
		        .field();

		AnnotatedFieldRuntime runtime = inspectedFieldRuntimes.get(name);
		if (runtime == null) {
			runtime = new AnnotatedFieldRuntime();
			inspectedFieldRuntimes.put(fieldName, runtime);
		}

		FieldFunction type = annotation.value();

//		System.out.printf("name=%s field=%s function=%s\n", name, fieldName, type);
		runtime.setFunction(type, method);

		return runtime;
	}

	/**
	 * @param c
	 */
	private void inspectHeader(Class<? extends JHeader> c) {
		Header annotation = c.getAnnotation(Header.class);
		if (annotation == null) {
			this.name = c.getSimpleName();
			this.nicname = this.name;

			return;
		}

		/*
		 * Check if we are a sub-header and set a flag so we don't try and register
		 * with JRegistry. Sub-header's are maintained by their parents, not
		 * JRegistry
		 */
		isSubHeader = c.getEnclosingClass() != null;

		this.name =
		    (annotation.name().isEmpty()) ? c.getSimpleName() : annotation.name();

		this.nicname =
		    (annotation.nicname().isEmpty()) ? this.name : annotation.nicname();
	}

	private JField[] inspectHeaderFields(Class<? extends JHeader> c) {

		for (Method m : c.getMethods()) {
			if (m.isAnnotationPresent(Field.class)) {
				inspectStaticFieldMethod(c, m);
			}

			if (m.isAnnotationPresent(FieldRuntime.class)) {
				inspectDynamicFieldMethod(c, m);
			}
		}

		for (AnnotatedField field : inspectedFields.values()) {
			AnnotatedFieldRuntime runtime =
			    inspectedFieldRuntimes.get(field.getName());
			if (runtime == null) {
				runtime = new AnnotatedFieldRuntime(field);
				inspectedFieldRuntimes.put(field.getName(), runtime);
			} else {
				runtime.setField(field);
			}

			runtime.configFrom(field);

			field.setRuntime(runtime);
		}

		/*
		 * Now merge subfields with their parents
		 */
		for (String k : inspectedSubFields.keySet()) {
			AnnotatedField field = inspectedFields.get(k);
			List<AnnotatedField> list = inspectedSubFields.get(k);

			if (field == null) {
				System.err.printf("Parent %s\n", k);
				continue;
			}

			field.addSubFields(list.toArray(new AnnotatedField[list.size()]));

			/*
			 * Now config sub-field's parent references and their runtimes
			 */
			for (AnnotatedField s : list) {
				AnnotatedFieldRuntime runtime = inspectedFieldRuntimes.get(s.getName());
				if (runtime == null) {
					runtime = new AnnotatedFieldRuntime(s);
					inspectedFieldRuntimes.put(s.getName(), runtime);
				} else {
					runtime.setField(field);
				}

				s.setParent(field);
				runtime.configFrom(s);

				s.setRuntime(runtime);

			}

		}

		return inspectedFields.values().toArray(new JField[inspectedFields.size()]);

	}

	/**
	 * @param c
	 * @param m
	 * @return
	 */
	private JField inspectStaticFieldMethod(Class<? extends JHeader> c, Method m) {
		Field a = m.getAnnotation(Field.class);

		String name = (a.name().isEmpty()) ? m.getName() : a.name();
		String nicname = (a.nicname().isEmpty()) ? name : a.nicname();
		String display = (a.display().isEmpty()) ? name : a.display();
		String format = a.format();
		String parent = a.parent();

		if (!parent.isEmpty() && format.isEmpty()) {
			format = "#bit#";
		}

		Style style = mapFormatToStyle(format);

//		System.out.printf(
//		    "field=%s, nic=%s, format=%s offset=%d length=%d parent=%s\n", name,
//		    nicname, format, a.offset(), a.length(), parent);

		AnnotatedField field = inspectedFields.get(name);
		if (field == null) {
			field =
			    new AnnotatedField(style, a.priority(), name, display, nicname, a
			        .units(), m);

			if (parent.isEmpty() == false) {
				field.setStyle(Style.INT_BITS);
				List<AnnotatedField> list = inspectedSubFields.get(parent);
				if (list == null) {
					list = new ArrayList<AnnotatedField>();
					inspectedSubFields.put(parent, list);
				}
				list.add(field);
			} else {
				inspectedFields.put(name, field);
			}
		}

		return field;
	}

	/**
	 * @param format
	 * @return
	 */
	private Style mapFormatToStyle(String format) {
		if (format.contains("%s")) {
			return Style.STRING;
		} else if (format.contains("%d")) {
			return Style.INT_DEC;
		} else if (format.contains("%x")) {
			return Style.INT_HEX;
		} else if (format.contains("#ip4#")) {
			return Style.BYTE_ARRAY_IP4_ADDRESS;
		} else if (format.contains("#ip4[]#")) {
			return Style.BYTE_ARRAY_ARRAY_IP4_ADDRESS;
		} else if (format.contains("#ip6#")) {
			return Style.BYTE_ARRAY_IP6_ADDRESS;
		} else if (format.contains("#mac#")) {
			return Style.BYTE_ARRAY_COLON_ADDRESS;
		} else if (format.contains("#hexdump#")) {
			return Style.BYTE_ARRAY_HEX_DUMP;
		} else if (format.contains("#bit#")) {
			return Style.INT_BITS;
		} else {
			return Style.STRING;
		}
	}

	/**
	 * Peers, associates a native packet buffer and scanner structure with this
	 * header. This header is unchanged while the header being passed in is
	 * rereferenced to point at this headers buffer and state structure.
	 * 
	 * @param header
	 *          the header to peer with this header
	 * @return number of bytes total that were peered with the supplied header
	 */
	public int peer(JHeader header) {
		this.state.peer(header.state);

		return super.peer(header, header.getOffset(), header.getLength());
	}

	/**
	 * Sets the packet that this header should be associated with
	 * 
	 * @param packet
	 *          packet to associate with this header
	 */
	public final void setPacket(JPacket packet) {
		this.packet = packet;
	}

	/**
	 * Gets a string with summary information about the header.
	 * 
	 * @return String with summary of the header
	 */
	public String toString() {
		return "(id=" + getId() + ", offset=" + getOffset() + ", length="
		    + getLength() + ")";
	}

	/**
	 * Allows a header to validate its values
	 */
	protected void validateHeader() {

	}
}
