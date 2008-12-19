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
package org.jnetpcap.packet.format;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jnetpcap.packet.HeaderDefinitionError;
import org.jnetpcap.packet.annotate.FieldRuntime;
import org.jnetpcap.packet.annotate.FieldRuntime.FieldFunction;


/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class AnnotatedFieldRuntime {

	private final AnnotatedField parent;

	private final Map<FieldFunction, AnnotatedFieldMethod> map =
	    new HashMap<FieldFunction, AnnotatedFieldMethod>();

	public AnnotatedFieldRuntime(AnnotatedField parent) {
		this.parent = parent;

	}

	public void setFunction(AnnotatedFieldMethod method) {
		final FieldFunction function = method.getFunction();

		if (map.containsKey(function)) {
			throw new HeaderDefinitionError(method.getMethod()
			    .getDeclaringClass(), "duplicate " + function
			    + " method declarations for field " + parent.getName());
		}

		/*
		 * Set default values if they were declared with the @Field annotation. This
		 * saves having to make the actual call to the header.
		 */
		method.configFromField(parent);
		map.put(function, method);
	}

	/**
	 * 
	 */
	public void finishProcessing(List<HeaderDefinitionError> errors) {

		/*
		 * Time to optimize and fill in the blanks if there are any
		 */
		for (FieldFunction f: FieldFunction.values()) {
			
			try {
			if (map.containsKey(f) == false) {
				map.put(f, AnnotatedFieldMethod.generateFunction(f, parent));
			}
			} catch (HeaderDefinitionError e) {
				errors.add(e);
			}
		}
	}

	/**
   * @return
   */
  public Map<FieldFunction, AnnotatedFieldMethod> getFunctionMap() {
	  return map;
  }

}
