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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.JScan;
import org.jnetpcap.packet.annotate.Scanner;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class AnnotatedScannerMethod
    extends AnnotatedMethod {

	private final static Map<Class<?>, AnnotatedScannerMethod[]> cache =
	    new HashMap<Class<?>, AnnotatedScannerMethod[]>();

	public static AnnotatedScannerMethod[] inspectJHeaderClass(
	    Class<? extends JHeader> c) {

		if (cache.containsKey(c)) {
			return cache.get(c);
		}

		final Method[] ms = getMethods(c, Scanner.class);

		if (ms.length > 1) {
			throw new HeaderDefinitionError(c, "too many scanners defined");

		} else if (ms.length == 1) {
			AnnotatedScannerMethod[] m =
			    new AnnotatedScannerMethod[] { new AnnotatedScannerMethod(ms[0], c) };
			cache.put(c, m);

			return m;

		} else {
			AnnotatedScannerMethod[] m = new AnnotatedScannerMethod[0];
			cache.put(c, m);

			return m;
		}
	}

	public static AnnotatedScannerMethod[] inspectClass(Class<? extends JHeader> c) {

		if (cache.containsKey(c)) {
			return cache.get(c);
		}

		List<AnnotatedScannerMethod> list =
		    new ArrayList<AnnotatedScannerMethod>(20);

		for (Method method : getMethods(c, Scanner.class)) {
			Scanner a = method.getAnnotation(Scanner.class);
			Class<? extends JHeader> clazz =
			    (a.value() == JHeader.class) ? c : a.value();

			if (JHeader.class.isAssignableFrom(c) == false) {
				throw new HeaderDefinitionError(c, "non JHeader based classes, "
				    + "must declare protocol class in @Scanner annotation");
			}

			list.add(new AnnotatedScannerMethod(method, clazz));
		}

		AnnotatedScannerMethod[] m =
		    list.toArray(new AnnotatedScannerMethod[list.size()]);
		cache.put(c, m);

		return m;
	}

	public static AnnotatedScannerMethod[] inspectObject(Object container) {
		Class<?> c = container.getClass();

		if (cache.containsKey(c)) {
			return cache.get(c);
		}

		List<AnnotatedScannerMethod> list =
		    new ArrayList<AnnotatedScannerMethod>(20);

		for (Method method : getMethods(c, Scanner.class)) {
			Scanner a = method.getAnnotation(Scanner.class);
			if (a.value() == JHeader.class) {
				throw new HeaderDefinitionError(c, "non JHeader based classes, "
				    + "must declare protocol class in @Scanner annotation");
			}

			list.add(new AnnotatedScannerMethod(method, a.value(), container));
		}

		AnnotatedScannerMethod[] m =
		    list.toArray(new AnnotatedScannerMethod[list.size()]);
		cache.put(c, m);

		return m;
	}

	private final int id;

	/**
	 * @param method
	 */
	private AnnotatedScannerMethod(Method method, Class<? extends JHeader> c) {
		super(method);

		this.id = JRegistry.lookupId(c);
	}

	/**
	 * @param method
	 * @param value
	 * @param container
	 */
	public AnnotatedScannerMethod(Method method, Class<? extends JHeader> c,
	    Object container) {
		super(method, container);

		this.id = JRegistry.lookupId(c);
	}

	public void scan(JScan scan) {
		try {
			method.invoke(object, scan);

		} catch (final IllegalArgumentException e) {
			throw new IllegalStateException(e);
		} catch (final IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (final InvocationTargetException e) {
			throw new AnnotatedMethodException(declaringClass, e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.annotate.AnnotatedMethod#validateSignature(java.lang.reflect.Method)
	 */
	@Override
	protected void validateSignature(Method method) {
		final Class<?> declaringClass = method.getDeclaringClass();

		if (method.isAnnotationPresent(Scanner.class) == false) {
			throw new AnnotatedMethodException(declaringClass,
			    "@Scanner annotation missing for " + method.getName() + "()");
		}

		/*
		 * Now make sure it has the right signature of: <code>static int
		 * name(JBuffer, int)</code.
		 */
		final Class<?>[] sig = method.getParameterTypes();
		if (sig.length != 1 || sig[0] != JScan.class) {
			throw new AnnotatedMethodException(declaringClass,
			    "Invalid signature for " + method.getName() + "()");
		}

		if (object == null && (method.getModifiers() & Modifier.STATIC) == 0) {
			throw new AnnotatedMethodException(declaringClass, method.getName()
			    + "()" + " must be declared static");
		}
	}

	public int getId() {
		return this.id;
	}
}
