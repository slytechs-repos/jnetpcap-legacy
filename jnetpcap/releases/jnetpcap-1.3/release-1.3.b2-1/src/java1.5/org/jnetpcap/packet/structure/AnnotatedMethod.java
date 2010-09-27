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

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class AnnotatedMethod {

	protected final Method method;
	
	protected boolean isMapped = false;
	
	public void setIsMapped(boolean state) {
		this.isMapped = state;
	}

	protected final Class<?> declaringClass;

	protected final Object object;

	private static HashMap<Integer, Method[]> cache =
	    new HashMap<Integer, Method[]>(20);

	public AnnotatedMethod() {
		this.method = null;
		this.declaringClass = null;
		this.object = null;
		this.isMapped = false;
	}

	public AnnotatedMethod(Method method, Object object) {
		this.object = object;
		this.method = method;
		this.declaringClass = method.getDeclaringClass();

	}

	public AnnotatedMethod(Method method) {
		this.method = method;
		this.declaringClass = method.getDeclaringClass();
		this.object = null;

		validateSignature(method);
	}

	public Method getMethod() {
		return this.method;
	}

	protected abstract void validateSignature(Method method);

	public String toString() {
		if (method == null) {
			return "";
		} else {
			return declaringClass.getSimpleName() + "." + method.getName() + "()";
		}
	}


	public static Method[] getMethods(
	    Class<?> c,
	    Class<? extends Annotation> annotation) {

		final int hash = c.hashCode() + annotation.hashCode();
		if (cache.containsKey(hash)) {
			return cache.get(hash);
		}

		List<Method> methods = new ArrayList<Method>(50);
		for (Method method : c.getMethods()) {
			if (method.isAnnotationPresent(annotation)) {
				methods.add(method);
			}
		}


		Method[] m =  methods.toArray(new Method[methods.size()]);
		cache.put(hash, m);
		return m;
	}
}
