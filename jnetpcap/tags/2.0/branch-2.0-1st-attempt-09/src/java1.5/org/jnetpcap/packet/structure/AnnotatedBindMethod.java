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
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.annotate.Bind;


/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class AnnotatedBindMethod
    extends AnnotatedMethod {

	private final static Map<Class<?>, AnnotatedBindMethod[]> cache =
	    new HashMap<Class<?>, AnnotatedBindMethod[]>();

	private static void checkSignature(final Method method) {

		final Class<?> declaringClass = method.getDeclaringClass();

		if (method.isAnnotationPresent(Bind.class) == false) {
			throw new AnnotatedMethodException(declaringClass,
			    "@Bind annotation missing for " + method.getName() + "()");
		}

		/*
		 * Now make sure it has the right signature of: <code>static int
		 * name(JBuffer, int)</code.
		 */
		final Class<?>[] sig = method.getParameterTypes();
		if (sig.length != 2 || sig[0] != JPacket.class
		    || sig[1].isAssignableFrom(JHeader.class)) {
			throw new AnnotatedMethodException(declaringClass,
			    "Invalid signature for " + method.getName() + "()");
		}

		if ((method.getModifiers() & Modifier.STATIC) == 0) {
			throw new AnnotatedMethodException(declaringClass, method.getName()
			    + "()" + " must be declared static");
		}
	}

	private static void checkNonStaticSignature(final Method method) {

		final Class<?> declaringClass = method.getDeclaringClass();

		if (method.isAnnotationPresent(Bind.class) == false) {
			throw new AnnotatedMethodException(declaringClass,
			    "@Bind annotation missing for " + method.getName() + "()");
		}

		/*
		 * Now make sure it has the right signature of: <code>static int
		 * name(JBuffer, int)</code.
		 */
		final Class<?>[] sig = method.getParameterTypes();
		if (sig.length != 2 || sig[0] != JPacket.class
		    || sig[1].isAssignableFrom(JHeader.class)) {
			throw new AnnotatedMethodException(declaringClass,
			    "Invalid signature for " + method.getName() + "()");
		}

		if ((method.getModifiers() & Modifier.STATIC) != 0) {
			throw new AnnotatedMethodException(declaringClass, method.getName()
			    + "()" + " can not be declared static");
		}
	}

	public static void clearCache() {
		cache.clear();
	}

	public static AnnotatedBindMethod[] inspectClass(
	    final Class<?> c,
	    final List<HeaderDefinitionError> errors) {

		if (cache.containsKey(c)) {
			return cache.get(c);
		}

		/*
		 * We use a linked list as the normal Array.asList comes up with a version
		 * that doesn't support the Iterator.remove() method. ArrayList and LinkList
		 * both do.
		 */
		AnnotatedBindMethod[] unchecked = inspectAnyClass(c, errors);
		final List<AnnotatedBindMethod> list =
		    new LinkedList<AnnotatedBindMethod>(Arrays.asList(unchecked));

		for (final Iterator<AnnotatedBindMethod> i = list.iterator(); i.hasNext();) {
			final AnnotatedBindMethod b = i.next();
			/*
			 * Also need to check and make sure that for general classes, there is
			 * also a "from" parameter, which does not have to be present int JHeader
			 * declaring class case.
			 */
			final Bind bind = b.getMethod().getAnnotation(Bind.class);
			final Class<? extends JHeader> source = bind.from();

			if (source == JHeader.class) {
				errors.add(new HeaderDefinitionError(c,
				    "missing annotated 'from' declaration for method "
				        + b.getMethod().getName() + "()"));

				i.remove();
			}
		}

		/*
		 * Now update cache after our check since removed values may have also been
		 * cached.
		 */
		final AnnotatedBindMethod[] bounds =
		    list.toArray(new AnnotatedBindMethod[list.size()]);

		cache.put(c, bounds);

		return bounds;
	}

	private static <T extends JHeader> AnnotatedBindMethod[] inspectAnyClass(
	    final Class<?> c,
	    final List<HeaderDefinitionError> errors) {

		if (cache.containsKey(c)) {
			return cache.get(c);
		}

		final List<AnnotatedBindMethod> list = new ArrayList<AnnotatedBindMethod>();
		Class<? extends JHeader> target = null;

		for (final Method method : c.getMethods()) {

			try {
				if (method.isAnnotationPresent(Bind.class)) {

					checkSignature(method);

					final Bind bind = method.getAnnotation(Bind.class);
					target = bind.to();
					final AnnotatedBindMethod boundMethod =
					    new AnnotatedBindMethod(target, method);

					list.add(boundMethod);
				}
			} catch (final AnnotatedMethodException e) {
				errors.add(e);
			}

		}

		final AnnotatedBindMethod[] isBounds =
		    list.toArray(new AnnotatedBindMethod[list.size()]);

		cache.put(c, isBounds);

		return isBounds;
	}

	public static AnnotatedBindMethod[] inspectObject(
	    final Object object,
	    final List<HeaderDefinitionError> errors) {

		Class<?> c = object.getClass();

		if (cache.containsKey(c)) {
			return cache.get(c);
		}

		final List<AnnotatedBindMethod> list = new ArrayList<AnnotatedBindMethod>();
		Class<? extends JHeader> target = null;

		if (c.getSuperclass() != Object.class) {
			errors.add(new AnnotatedMethodException(
			    "bindings using annonymous classes can only extend Object class"));

			return new AnnotatedBindMethod[0];
		}

		for (final Method method : c.getMethods()) {

			try {
				if (method.isAnnotationPresent(Bind.class)) {

					checkNonStaticSignature(method);

					final Bind bind = method.getAnnotation(Bind.class);
					target = bind.to();
					final AnnotatedBindMethod boundMethod =
					    new AnnotatedBindMethod(target, method, object);

					list.add(boundMethod);
				}
			} catch (final AnnotatedMethodException e) {
				errors.add(e);
			}

		}

		final AnnotatedBindMethod[] binds =
		    list.toArray(new AnnotatedBindMethod[list.size()]);

		cache.put(c, binds);

		return binds;
	}

	public static <T extends JHeader> AnnotatedBindMethod[] inspectJHeaderClass(
	    final Class<? extends JHeader> c,
	    final List<HeaderDefinitionError> errors) {

		return inspectAnyClass(c, errors);
	}

	private AnnotatedBindMethod(final Class<? extends JHeader> target,
	    final Method method, final Object object) {
		super(method, object);
	}

	private AnnotatedBindMethod(final Class<? extends JHeader> target,
	    final Method method) {
		super(method);
	}

	public boolean isBound(
	    final JPacket packet,
	    final int offset,
	    final JHeader header) {

		try {
			return (Boolean) method.invoke(object, packet, header);
		} catch (final IllegalArgumentException e) {
			throw new IllegalStateException(e);
		} catch (final IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (final InvocationTargetException e) {
			throw new AnnotatedMethodException(declaringClass, e);
		}
	}

	@Override
	protected void validateSignature(final Method method) {
		
		if (object == null) {
			checkSignature(method);
		} else {
			checkNonStaticSignature(method);
		}
	}
}
