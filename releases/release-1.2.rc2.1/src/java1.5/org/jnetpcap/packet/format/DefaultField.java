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

import org.jnetpcap.packet.structure.AnnotatedField;
import org.jnetpcap.packet.structure.JField;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class DefaultField
    extends JField {

	private DefaultField(AnnotatedField field, DefaultField[] children) {
		super(field, children);
	}

	public static DefaultField fromAnnotatedField(AnnotatedField field) {

		DefaultField[] children = new DefaultField[field.getSubFields().size()];
		int i = 0;
		for (AnnotatedField f : field.getSubFields()) {
			children[i++] = fromAnnotatedField(f);
		}

		JField.sortFieldByOffset(children, null, false);

		return new DefaultField(field, children);
	}

	/**
	 * @param fields
	 * @return
	 */
	public static JField[] fromAnnotatedFields(AnnotatedField[] fields) {
		JField[] f = new JField[fields.length];

		for (int i = 0; i < fields.length; i++) {
			f[i] = fromAnnotatedField(fields[i]);
		}

		return f;
	}
}
