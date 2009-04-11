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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jnetpcap.packet.JBinding;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.annotate.Bind;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class AnnotatedBinding implements JBinding {

	private final static Map<Class<?>, JBinding[]> cache =
	    new HashMap<Class<?>, JBinding[]>();

	public static void clearCache() {
		cache.clear();
	}

	private static JHeader createHeaderFromClass(Class<? extends JHeader> c) {
		try {
			JHeader header = c.newInstance();
			return header;
		} catch (InstantiationException e) {
			throw new HeaderDefinitionError(c, "problem in the default constructor",
			    e);
		} catch (IllegalAccessException e) {
			throw new HeaderDefinitionError(c, "problem in the default constructor",
			    e);
		}
	}

	public static JBinding[] inspectClass(
	    Class<?> c,
	    List<HeaderDefinitionError> errors) {

		if (cache.containsKey(c)) {
			return cache.get(c);
		}

		AnnotatedBindMethod[] bindMethods =
		    AnnotatedBindMethod.inspectClass(c, errors);

		return createBindings(c, bindMethods, errors);
	}

	private static JBinding[] createBindings(
	    Class<?> c,
	    AnnotatedBindMethod[] bindMethods,
	    List<HeaderDefinitionError> errors) {

		List<JBinding> list = new ArrayList<JBinding>();
		Class<? extends JHeader> target = null;

		for (AnnotatedBindMethod boundMethod : bindMethods) {

			try {

				Bind bind = boundMethod.getMethod().getAnnotation(Bind.class);
				target = bind.to();
				Class<? extends JHeader> source = bind.from();
				Class<? extends JHeader>[] dependencies = bind.dependencies();

				AnnotatedHeaderLengthMethod getLengthMethod =
				    AnnotatedHeaderLengthMethod.inspectClass(target);

				list.add(new AnnotatedBinding(c, source, target, boundMethod,
				    getLengthMethod, dependencies));

			} catch (AnnotatedMethodException e) {
				errors.add(e);
			}

		}

		JBinding[] bindings = list.toArray(new JBinding[list.size()]);
		cache.put(c, bindings);

		return bindings;
	}

	public static <T extends JHeader> JBinding[] inspectJHeaderClass(
	    Class<T> c,
	    List<HeaderDefinitionError> errors) {

		if (cache.containsKey(c)) {
			return cache.get(c);
		}

		AnnotatedBindMethod[] bindMethods =
		    AnnotatedBindMethod.inspectJHeaderClass(c, errors);

		Class<T> source = c;
		List<JBinding> list = new ArrayList<JBinding>();
		Class<? extends JHeader> target = null;

		for (AnnotatedBindMethod boundMethod : bindMethods) {

			try {

				Bind bind = boundMethod.getMethod().getAnnotation(Bind.class);
				target = bind.to();
				Class<? extends JHeader>[] dependencies = bind.dependencies();

				AnnotatedHeaderLengthMethod getLengthMethod =
				    AnnotatedHeaderLengthMethod.inspectClass(target);

				list.add(new AnnotatedBinding(c, source, target, boundMethod,
				    getLengthMethod, dependencies));

			} catch (AnnotatedMethodException e) {
				errors.add(e);
			}
		}

		JBinding[] bindings = list.toArray(new JBinding[list.size()]);
		cache.put(c, bindings);

		return bindings;
	}

	private final AnnotatedBindMethod annotatedBound;

	private final Class<?> definitionClass;

	protected final int[] dependencies;

	/**
	 * Our working protocol header that we use to peer with packet and dispatch to
	 * isBound method.
	 */
	private final JHeader header;

	private final int sourceId;

	private final Class<? extends JHeader> targetClass;

	private final int targetId;

	private AnnotatedBinding(Class<?> definitionClass,
	    Class<? extends JHeader> source, Class<? extends JHeader> target,
	    AnnotatedBindMethod bindingMethod,
	    AnnotatedHeaderLengthMethod lengthMethod,
	    Class<? extends JHeader>... dependencies) {

		this.definitionClass = definitionClass;
		this.targetClass = target;
		this.annotatedBound = bindingMethod;
		this.dependencies = new int[dependencies.length];
		this.sourceId = JRegistry.lookupId(source);
		this.targetId = JRegistry.lookupId(target);

		/*
		 * Convert dependencies array of classes to array int IDs
		 */
		int i = 0;
		for (Class<? extends JHeader> c : dependencies) {
			this.dependencies[i++] = JRegistry.lookupId(c);
		}

		header = createHeaderFromClass(target);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JBinding#getSourceId()
	 */
	public int getSourceId() {
		return this.sourceId;
	}

	public Class<? extends JHeader> getTargetClass() {
		return targetClass;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JBinding#getTargetId()
	 */
	public int getTargetId() {
		return targetId;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JBinding#isBound(org.jnetpcap.packet.JPacket, int)
	 */
	public boolean isBound(JPacket packet, int offset) {
		
		packet.getHeader(header);

		return annotatedBound.isBound(packet, offset, header);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JDependency#listDependencies()
	 */
	public int[] listDependencies() {
		return dependencies;
	}

	public String toString() {
		String def = this.definitionClass.getSimpleName();
		String method = this.annotatedBound.getMethod().getName();
		String target = this.targetClass.getSimpleName();

		return def + "." + method + "(JPacket packet, " + target + " header):"
		    + "boolean";
	}

	/**
	 * @param bindingSuite
	 * @param errors
	 * @return
	 */
	public static JBinding[] inspectClass(
	    Object bindingSuite,
	    List<HeaderDefinitionError> errors) {
		return inspectClass(bindingSuite.getClass(), errors);
	}

	/**
	 * @param object
	 * @param errors
	 * @return
	 */
	public static JBinding[] inspectObject(
	    Object object,
	    List<HeaderDefinitionError> errors) {

		Class<?> c = object.getClass();

		if (cache.containsKey(c)) {
			return cache.get(c);
		}

		AnnotatedBindMethod[] bindMethods =
		    AnnotatedBindMethod.inspectObject(object, errors);

		return createBindings(c, bindMethods, errors);

	}

}
