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
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JSubHeader;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.FieldRuntime;
import org.jnetpcap.packet.annotate.FieldSetter;
import org.jnetpcap.packet.annotate.Header;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class AnnotatedHeader {

	private final static Map<Class<?>, AnnotatedHeader> cache =
	    new HashMap<Class<?>, AnnotatedHeader>();

	private static List<Class<?>> getSubHeaderClasses(Class<?> c, String prefix) {

		final List<Class<?>> list = new ArrayList<Class<?>>();

		for (final Class<?> s : c.getClasses()) {

			if (s == c) { // prevent infinate loop
				continue;
			}

			if (s.isAnnotationPresent(Header.class)) {
				list.add(s);

				/*
				 * We're interested in direct sub-header's and not sub-headers of
				 * sub-headers. Again, a sub header has @Header annotation on it, not
				 * just the java declaration class within a class. We're looking at the
				 * hierachy of @Header type sub-headers. Each sub-headers evaluates its
				 * own sub-headers in a seperate scan, that is why we stop here.
				 */
				continue;
			}

			list.addAll(getSubHeaderClasses(s, prefix + "." + s.getSimpleName()));
		}

		return list;
	}

	/**
	 * @Header is optional on top level header. It defaults to class name as
	 *         header name
	 * @param c
	 * @return
	 */
	private static AnnotatedHeader inspectHeaderAnnotation(
	    Class<? extends JHeader> c,
	    List<HeaderDefinitionError> errors) {

		AnnotatedHeader header = new AnnotatedHeader(c);

		if (c.isAnnotationPresent(Header.class)) {
			Header a = c.getAnnotation(Header.class);

			if (JHeader.class.isAssignableFrom(c) == false) {
				/*
				 * All headers must subclass JHeader.class, no exceptions.
				 */

				errors.add(new HeaderDefinitionError(c,
				    "header must subclass 'JHeader'"));
			}

			if (a.name().length() != 0) {
				header.name = a.name();
			} else {
				header.name = c.getSimpleName();
			}

			if (a.nicname().length() != 0) {
				header.nicname = a.nicname();
			} else {
				header.nicname = header.name;
			}

			if (a.id() != -1) {
				a.id();
			}

			if (a.parent() != JHeader.class) {
				header.parentClass = a.parent();
			}

			if (header.parentClass == null && c.getEnclosingClass() != null) {
				for (Class<?> p = c.getEnclosingClass(); p != null; p =
				    p.getEnclosingClass()) {

					if (p.isAnnotationPresent(Header.class)) {
						if (JHeader.class.isAssignableFrom(p) == false) {
							errors.add(new HeaderDefinitionError(c,
							    "parentClass header '" + p.getSimpleName()
							        + "' must subclass 'JHeader'"));
							break;
						}

						header.parentClass = p.asSubclass(JHeader.class);
						break;
					}
				}
			}

		} else {
			errors.add(new HeaderDefinitionError(c,
			    "header missing @Header annotation"));
		}

		return header;
	}

	public static AnnotatedHeader inspectJHeaderClass(
	    Class<? extends JHeader> c,
	    List<HeaderDefinitionError> errors) {

		if (cache.containsKey(c)) {
			return cache.get(c);
		}

		AnnotatedHeader header = inspectHeaderAnnotation(c, errors);

		/*
		 * Prepare by extracting all annotated methods and putting them into their
		 * own buckets
		 */
		List<Method> fieldMethods = new ArrayList<Method>(50);
		List<Method> setterMethods = new ArrayList<Method>(50);
		List<Method> runtimeMethods = new ArrayList<Method>(50);

		Map<String, AnnotatedField> fields =
		    new HashMap<String, AnnotatedField>(fieldMethods.size());

		for (Method m : c.getMethods()) {
			if (m.isAnnotationPresent(Field.class)) {
				fieldMethods.add(m);
			}

			if (m.isAnnotationPresent(FieldRuntime.class)) {
				runtimeMethods.add(m);
			}

			if (m.isAnnotationPresent(FieldSetter.class)) {
				setterMethods.add(m);
			}
		}

		/*
		 * First process @Field methods, then later add runtimes
		 */
		for (Method m : fieldMethods) {
			try {
				AnnotatedField field = AnnotatedField.inspectMethod(c, m);

				// System.out.printf("field=%s\n", field.getName());

				if (fields.containsKey(field.getName())) {
					throw new HeaderDefinitionError(c, "duplicate field "
					    + field.getName());
				}

				fields.put(field.getName(), field);
			} catch (HeaderDefinitionError e) {
				errors.add(e);
			}
		}

		/*
		 * Second process @FieldRuntime marked methods
		 */
		for (Method m : runtimeMethods) {
			try {
				AnnotatedFieldMethod function = AnnotatedFieldMethod.inspectMethod(m);

				AnnotatedField field = fields.get(function.getFieldName());
				if (field == null) {
					throw new HeaderDefinitionError(c, "runtime can not find field "
					    + function.getFieldName());
				}

				field.getRuntime().setFunction(function);
			} catch (HeaderDefinitionError e) {
				errors.add(e);
			}
		}

		/*
		 * Process sub-fields or compound fields
		 */
		;
		for (Iterator<AnnotatedField> i = fields.values().iterator(); i.hasNext();) {
			AnnotatedField field = i.next();
			try {
				if (field.isSubField() == false) {
					continue;
				}

				if (field.getParent().equals(field.getName())) {
					throw new HeaderDefinitionError(c,
					    "invalid parentClass name for sub-field " + field.getName());
				}

				AnnotatedField parent = fields.get(field.getParent());
				if (parent == null) {
					throw new HeaderDefinitionError(c, "can not find parentClass '"
					    + field.getParent() + "' for sub field '" + field.getName() + "'");
				}

				parent.addSubField(field);

				i.remove();

			} catch (HeaderDefinitionError e) {
				errors.add(e);
			}
		}

		/*
		 * Last, tell all the fields we are done processing and let them finish up
		 * whatever they need to
		 */
		for (AnnotatedField field : fields.values()) {
			field.finishProcessing(errors);
		}

		/*
		 * Check for sub-headers. We need to walk the entire class within class
		 * hierachy looking for classes marked with @Header annotation. Unless they
		 * have the "parentClass" parameter defined, they automatically become the
		 * sub-header of us. The sub-class must also extend JSubHeader class, if it
		 * doesn't we skip it and report an error.
		 */
		List<Class<?>> subClasses = getSubHeaderClasses(c, c.getSimpleName());
		List<AnnotatedHeader> subHeaders =
		    new ArrayList<AnnotatedHeader>(subClasses.size());
		for (Class<?> s : subClasses) {

			if (c == s) { // Prevent infinite loop
				continue;
			}

			if (JSubHeader.class.isAssignableFrom(s) == false) {
				errors.add(new HeaderDefinitionError(c, "skipping sub-header "
				    + s.getSimpleName()
				    + ". The sub-header must subclass JSubHeader class"));
				continue;
			}

			// System.out.printf("inspecting sub-header %s\n", s.getSimpleName());

			subHeaders
			    .add(inspectJHeaderClass(s.asSubclass(JSubHeader.class), errors));

		}

		header.saveSubHeaders(subHeaders.toArray(new AnnotatedHeader[subHeaders
		    .size()]));

		header.saveFields(fields.values()
		    .toArray(new AnnotatedField[fields.size()]));

		try {
			AnnotatedHeaderLengthMethod.inspectClass(c);
		} catch (AnnotatedMethodException e) {
			errors.add(new HeaderDefinitionError(c, e));
		}

		if (errors.isEmpty()) {
			cache.put(c, header);
		}

		return header;
	}

	private Class<? extends JHeader> clazz;

	private AnnotatedField[] fields;

	private final Header headerAnnotation;

	private AnnotatedHeader[] headers;

	private String name;

	private String nicname;

	private Class<? extends JHeader> parentClass = null;

	private AnnotatedHeader parent;

	private AnnotatedHeader(Class<? extends JHeader> c) {
		this.headerAnnotation = c.getAnnotation(Header.class);
		this.clazz = c;
	}

	public AnnotatedField[] getFields() {
		return fields;
	}

	/**
	 * @return
	 */
	public Class<? extends JHeader> getHeaderClass() {
		return this.clazz;
	}

	public final AnnotatedHeader[] getHeaders() {
		return this.headers;
	}

	/**
	 * @return
	 */
	public int getId() {
		return this.headerAnnotation.id();
	}

	/**
	 * @return
	 */
	public String getName() {
		return this.name;
	}

	public final String getNicname() {
		return this.nicname;
	}

	/**
	 * @param fields
	 */
	private void saveFields(AnnotatedField[] fields) {
		this.fields = fields;

	}

	/**
	 * @param headers
	 */
	private void saveSubHeaders(AnnotatedHeader[] headers) {
		this.headers = headers;

		for (AnnotatedHeader header : headers) {
			header.setParent(this);
		}
	}

	public final AnnotatedHeader getParent() {
		return this.parent;
	}

	public boolean isSubHeader() {
		return this.parent != null;
	}

	/**
	 * @param parentClass
	 */
	private void setParent(AnnotatedHeader parent) {
		this.parent = parent;
	}
}
