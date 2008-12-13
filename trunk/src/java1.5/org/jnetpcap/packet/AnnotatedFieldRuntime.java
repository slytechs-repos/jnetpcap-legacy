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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.FieldRuntime.FieldFunction;
import org.jnetpcap.packet.format.JField;
import org.jnetpcap.packet.format.JFieldRuntime;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class AnnotatedFieldRuntime implements JFieldRuntime<JHeader, Object> {

	private final Map<FieldFunction, Method> functions =
	    new HashMap<FieldFunction, Method>();

	private int staticOffset;

	private int staticLength;

	private String staticDescription;

	private JField field;
	
	public AnnotatedFieldRuntime() {
		
	}

	public AnnotatedFieldRuntime(JField field) {
		this.field = field;
	}

	public void setFunction(FieldFunction type, Method function) {
		functions.put(type, function);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFieldRuntime#getLength()
	 */
	public int getLength(JHeader header) {
		Method m = functions.get(FieldFunction.LENGTH);
		if (m != null) {
			try {
				return (int) (Integer) m.invoke(header);

			} catch (IllegalArgumentException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalAccessException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvocationTargetException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		return staticLength;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFieldRuntime#getMask()
	 */
	@SuppressWarnings("unchecked")
	public int getMask(JHeader header) {
		Method m = functions.get(FieldFunction.MASK);
		if (m != null) {
			try {
				return (int) (Integer) m.invoke(header);

			} catch (IllegalArgumentException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalAccessException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvocationTargetException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} else {
			/*
			 * Figure out the mask from offset and length
			 */
			final int length = getLength(header);
			final int offset = getOffset(header);
			int mask = 0;
			for (int i = offset; i < offset + length; i++) {
				mask |= (1 << i);
			}

			return mask;
		}

		return 0;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFieldRuntime#getOffset()
	 */
	public int getOffset(JHeader header) {
		Method m = functions.get(FieldFunction.LENGTH);
		if (m != null) {
			try {
				return (int) (Integer) m.invoke(header);

			} catch (IllegalArgumentException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalAccessException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvocationTargetException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		return staticOffset;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFieldRuntime#hasField(org.jnetpcap.packet.JHeader)
	 */
	public boolean hasField(JHeader header) {
		Method m = functions.get(FieldFunction.CHECK);
		if (m != null) {
			try {
				return (boolean) (Boolean) m.invoke(header);

			} catch (IllegalArgumentException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalAccessException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvocationTargetException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		return true;
	}

	public boolean isValueSet() {
		return functions.containsKey(FieldFunction.VALUE);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFieldRuntime#value(org.jnetpcap.packet.JHeader)
	 */
	public Object value(JHeader header) {
		Method m = functions.get(FieldFunction.VALUE);
		if (m != null) {
			try {
				return m.invoke(header);

			} catch (IllegalArgumentException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalAccessException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvocationTargetException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException(
		    "Field's runtime not linked to any field");
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFieldRuntime#valueDescription(org.jnetpcap.packet.JHeader)
	 */
	public String valueDescription(JHeader header) {
		Method m = functions.get(FieldFunction.DESCRIPTION);
		if (m != null) {
			try {
				return (String) m.invoke(header);

			} catch (IllegalArgumentException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalAccessException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvocationTargetException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		return staticDescription;
	}

	/**
	 * @param field
	 */
	public void configFrom(AnnotatedField field) {
		Method method = field.getMethod();
		Field annotation = method.getAnnotation(Field.class);

		this.staticOffset = annotation.offset();
		this.staticLength = annotation.length();
		this.staticDescription =
		    (annotation.description().isEmpty()) ? null : annotation.description();

		if (functions.containsKey(FieldFunction.VALUE) == false) {
			setFunction(FieldFunction.VALUE, method);
		}
	}

	public final JField getField() {
		return this.field;
	}

	public final void setField(JField field) {
		this.field = field;
	}

}
