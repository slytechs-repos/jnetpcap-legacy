/**
 * Copyright (C) 2009 Sly Technologies, Inc. This library is free software; you
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
package org.jnetpcap.nio;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JNILoader {

	/**
	 * Finds a signature of a field.
	 * 
	 * @param clazz
	 *          field's declaring class
	 * @param name
	 *          name of the field
	 * @return a JNI signature of the return type
	 * @throws SecurityException
	 *           if no permission
	 * @throws NoSuchFieldException
	 *           if field by name not found
	 */
	public static String findFieldSignature(Class<?> clazz, String name)
	    throws SecurityException, NoSuchFieldException {

		Field f = clazz.getField(name);
		Class<?> type = f.getType();

		return toSignature(type);
	}

	/**
	 * Finds a method and returns its complete JNI signature.
	 * 
	 * @param clazz
	 *          class defining the method
	 * @param name
	 *          name of the method
	 * @return JNI signtature of the method
	 * @throws NoSuchMethodException
	 *           if method is not found or if more than one method is found
	 */
	public static String findMethodSignature(Class<?> clazz, String name)
	    throws NoSuchMethodException {

		StringBuilder b = new StringBuilder();

		Method m = findMethod(clazz, name);

		b.append('(');
		for (Class<?> c : m.getParameterTypes()) {
			b.append(toSignature(c));
		}
		b.append(')');

		b.append(m.getReturnType());

		return b.toString();
	}

	/**
	 * Finds a single method with the supplied name. If more than one method with
	 * the same name is found, an exception is thrown.
	 * 
	 * @param clazz
	 *          class dfining the method
	 * @param name
	 *          name of the method
	 * @return method if found otherwise null
	 * @throws NoSuchMethodException
	 *           if not found or multiple methods with the same name are found
	 */
	public static Method findMethod(Class<?> clazz, String name)
	    throws NoSuchMethodException {

		Method found = null;
		for (Method m : clazz.getMethods()) {
			if (name.equals(m.getName())) {
				if (found != null) {
					throw new NoSuchMethodException("multiple methods with this name "
					    + name + " in class " + clazz.getSimpleName());
				}
				found = m;
			}
		}

		return found;
	}

	/**
	 * Converts a class, including primitive classes, into a JNI signature
	 * 
	 * @param type
	 *          class to convert
	 * @return string representing a JNI signature
	 */
	public static String toSignature(Class<?> type) {
		if (type == void.class) {
			return "V";
		} else if (type == byte.class) {
			return "B";
		} else if (type == boolean.class) {
			return "Z";
		} else if (type == char.class) {
			return "C";
		} else if (type == short.class) {
			return "S";
		} else if (type == int.class) {
			return "I";
		} else if (type == long.class) {
			return "J";
		} else if (type == float.class) {
			return "F";
		} else if (type == double.class) {
			return "D";
		} else {
			return "L" + type.getCanonicalName() + ";";
		}

	}
}
