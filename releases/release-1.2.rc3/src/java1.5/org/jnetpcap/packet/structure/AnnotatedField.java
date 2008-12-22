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
package org.jnetpcap.packet.structure;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.format.JFormatter.Priority;
import org.jnetpcap.packet.format.JFormatter.Style;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class AnnotatedField {

	/**
	 * @param c
	 * @param method
	 */
	private static void checkSingature(Class<? extends JHeader> c, Method method) {

		if (method.isAnnotationPresent(Field.class) == false) {
			throw new AnnotatedMethodException(c,
			    "missing @Field annotation on field " + method.getName());
		}
	}

	/**
	 * @param c
	 * @param m
	 * @return
	 */
	public static AnnotatedField inspectMethod(
	    Class<? extends JHeader> c,
	    Method m) {

		checkSingature(c, m);

		AnnotatedField field = new AnnotatedField(m);

		return field;
	}

	private final Field annotation;

	private final Class<?> declaringClass;

	private final Method method;

	private final AnnotatedFieldRuntime runtime;

	private final List<AnnotatedField> subFields =
	    new ArrayList<AnnotatedField>();

	private AnnotatedField(Method method) {
		this.method = method;
		this.annotation = method.getAnnotation(Field.class);
		this.runtime = new AnnotatedFieldRuntime(this);
		this.declaringClass = method.getDeclaringClass();
	}

	/**
	 * 
	 */
	public void finishProcessing(List<HeaderDefinitionError> errors) {
		runtime.finishProcessing(errors);

		for (AnnotatedField field : subFields) {
			field.finishProcessing(errors);
		}
	}

	/**
	 * @return
	 */
	public Class<?> getDeclaringClass() {
		return this.declaringClass;
	}

	public String getDescription() {
		return annotation.description();
	}

	public final String getDisplay() {
		return (annotation.display().length() == 0) ? getName() : annotation.display();
	}

	public final String getFormat() {
		if (isSubField() && annotation.format().length() == 0) {
			return "#bitfield#";
		}
		return (annotation.format().length() == 0) ? "%s" : annotation.format();
	}

	public int getLength() {
		return annotation.length();
	}

	/**
	 * @return
	 */
	public Method getMethod() {
		return this.method;
	}

	public final String getName() {
		return (annotation.name().length() == 0) ? method.getName() : annotation.name();
	}

	public final String getNicname() {
		return (annotation.nicname().length() == 0) ? getName() : annotation.nicname();
	}

	public int getOffset() {
		return annotation.offset();
	}

	/**
	 * @return
	 */
	public String getParent() {
		return annotation.parent();
	}

	public final AnnotatedFieldRuntime getRuntime() {
		return this.runtime;
	}

	public String getUnits() {
		return annotation.units();
	}

	/**
	 * @return
	 */
	public boolean isSubField() {
		return annotation.parent().length() != 0;
	}

	/**
	 * @param field
	 */
	public void addSubField(AnnotatedField field) {
		this.subFields.add(field);
	}

	/**
	 * @return
	 */
	public List<AnnotatedField> getSubFields() {
		return subFields;
	}

	/**
	 * @return
	 */
	public Style getStyle() {
		if (isSubField()) {
			return Style.INT_BITS;
		}
		
		return mapFormatToStyle(getFormat());
	}

	/**
	 * @return
	 */
	public Priority getPriority() {
		return annotation.priority();
	}

	private static Style mapFormatToStyle(String format) {
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
		} else if (format.contains("#textdump#")) {
			return Style.STRING_TEXT_DUMP;
		} else if (format.contains("#bitfield#")) {
			return Style.INT_BITS;
		} else {
			return Style.STRING;
		}
	}
}
