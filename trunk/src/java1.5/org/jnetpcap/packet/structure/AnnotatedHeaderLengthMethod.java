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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.Map;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class AnnotatedHeaderLengthMethod
    extends AnnotatedMethod {

	private final static Map<Class<?>, AnnotatedHeaderLengthMethod> cache =
	    new HashMap<Class<?>, AnnotatedHeaderLengthMethod>();

	public static AnnotatedHeaderLengthMethod inspectClass(
	    Class<? extends JHeader> c) {

		/*
		 * Check if we have this method cached for this class.
		 */
		if (cache.containsKey(c)) {
			return cache.get(c);
		}

		AnnotatedHeaderLengthMethod lengthMethod = null;

		Header header = c.getAnnotation(Header.class);
		if (header != null && header.length() != -1) {
			lengthMethod = new AnnotatedHeaderLengthMethod(c, header.length());
		}

		for (Method method : getMethods(c, HeaderLength.class)) {

			if (lengthMethod != null) {
				throw new AnnotatedMethodException(c, "duplicate: " + lengthMethod
				    + " and " + method.getName() + "()");
			}

			checkSignature(method);

			lengthMethod = new AnnotatedHeaderLengthMethod(method);
		}

		if (lengthMethod == null) {
			throw new AnnotatedMethodException(c,
			    "@HeaderLength annotated method not found");
		}

		cache.put(c, lengthMethod);
		return lengthMethod;
	}

	private int staticLength;

	private AnnotatedHeaderLengthMethod(Method method) {
		super(method);

		HeaderLength a = method.getAnnotation(HeaderLength.class);
		this.staticLength = a.value();
	}

	/**
	 * @param length
	 */
	public AnnotatedHeaderLengthMethod(Class<? extends JHeader> c, int length) {
		this.staticLength = length;
	}

	public int getHeaderLength(JBuffer buffer, int offset) {

		if (this.staticLength != -1) {
			return this.staticLength;
		}

		/*
		 * Invoke the static method: <code>public static int method(JBuffer, int)</code>
		 */
		try {
			int length = (int) (Integer) this.method.invoke(null, buffer, offset);
			return length;
		} catch (IllegalArgumentException e) {
			throw new IllegalStateException(e);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new AnnotatedMethodException(declaringClass, e);
		}
	}

	public final Method getMethod() {
		return this.method;
	}

	public boolean hasStaticLength() {
		return this.staticLength != -1;
	}

	protected void validateSignature(Method method) {
		checkSignature(method);
	}

	/**
	 * @param method
	 */
	private static void checkSignature(Method method) {

		Class<?> declaringClass = method.getDeclaringClass();

		if (method.isAnnotationPresent(HeaderLength.class) == false) {
			throw new AnnotatedMethodException(declaringClass,
			    "@HeaderLength annotation missing for " + method.getName() + "()");
		}

		/*
		 * Now make sure it has the right signature of: <code>static int
		 * name(JBuffer, int)</code.
		 */
		Class<?>[] t = method.getParameterTypes();
		if (t.length != 2 || t[0] != JBuffer.class || t[1] != int.class
		    || method.getReturnType() != int.class) {

			throw new AnnotatedMethodException(declaringClass,
			    "Invalid signature for " + method.getName() + "()");
		}

		if ((method.getModifiers() & Modifier.STATIC) == 0) {
			throw new AnnotatedMethodException(declaringClass, method.getName()
			    + "()" + " must be declared static");

		}
	}

	public static void clearCache() {
		cache.clear();
	}

	public String toString() {
		if (method == null) {
			return "@Header(length=" + staticLength + ")";
		} else {
			return super.toString();
		}
	}

}
