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

import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.packet.structure.HeaderDefinitionError;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class RegistryHeaderErrors
    extends RegistryException {

	private final List<HeaderDefinitionError> errors;

	private final Class<? extends JHeader> headerClass;

	public final HeaderDefinitionError[] getErrors() {
		return this.errors.toArray(new HeaderDefinitionError[errors.size()]);
	}

	public final Class<? extends JHeader> getHeaderClass() {
		return this.headerClass;
	}

	/**
	 * @param headerClass
	 * @param errors
	 */
	public RegistryHeaderErrors(Class<? extends JHeader> headerClass,
	    List<HeaderDefinitionError> errors, String msg) {
		super(msg);
		this.headerClass = headerClass;

		this.errors = new ArrayList<HeaderDefinitionError>(errors);
	}

	/**
	 * 
	 */
	private static final long serialVersionUID = -6414263503074702593L;

	@Override
	public String getMessage() {
		final StringBuilder out = new StringBuilder();

		for (final HeaderDefinitionError e : errors) {
			out.append(e.getMessage()).append('\n');
		}

		out.append('\n');
		out.append(super.getMessage());

		return out.toString();
	}

}
