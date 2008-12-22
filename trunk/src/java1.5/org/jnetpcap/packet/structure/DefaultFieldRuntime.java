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

import java.util.Map;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.annotate.FieldRuntime.FieldFunction;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class DefaultFieldRuntime implements JFieldRuntime<JHeader, Object> {

	private final AnnotatedFieldMethod length;

	private final AnnotatedFieldMethod offset;

	private final AnnotatedFieldMethod description;

	private final AnnotatedFieldMethod value;

	private final AnnotatedFieldMethod mask;

	private final AnnotatedFieldMethod check;

	public DefaultFieldRuntime(AnnotatedFieldRuntime runtime) {

		Map<FieldFunction, AnnotatedFieldMethod> map = runtime.getFunctionMap();
		
		length = map.get(FieldFunction.LENGTH);
		offset = map.get(FieldFunction.OFFSET);
		description = map.get(FieldFunction.DESCRIPTION);
		value = map.get(FieldFunction.VALUE);
		mask = map.get(FieldFunction.MASK);
		check = map.get(FieldFunction.CHECK);

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFieldRuntime#getLength(org.jnetpcap.packet.JHeader)
	 */
	public int getLength(JHeader header) {
		return length.intMethod(header);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFieldRuntime#getMask(org.jnetpcap.packet.JHeader)
	 */
	public int getMask(JHeader header) {
		return mask.intMethod(header);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFieldRuntime#getOffset(org.jnetpcap.packet.JHeader)
	 */
	public int getOffset(JHeader header) {
		return offset.intMethod(header);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFieldRuntime#hasField(org.jnetpcap.packet.JHeader)
	 */
	public boolean hasField(JHeader header) {
		return check.booleanMethod(header);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFieldRuntime#value(org.jnetpcap.packet.JHeader)
	 */
	public Object value(JHeader header) {
		return value.objectMethod(header);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFieldRuntime#valueDescription(org.jnetpcap.packet.JHeader)
	 */
	public String valueDescription(JHeader header) {
		return description.stringMethod(header);
	}

}
