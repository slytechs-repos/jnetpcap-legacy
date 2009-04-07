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
package org.jnetpcap.util;

import java.beans.PropertyChangeEvent;

/**
 * An event object and event related utilities.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JEvent {

	public static int intValue(PropertyChangeEvent evt) {
		return Integer.parseInt((String) evt.getNewValue());
	}

	public static long longValue(PropertyChangeEvent evt) {
		return Long.parseLong((String) evt.getNewValue());
	}

	public static boolean booleanValue(PropertyChangeEvent evt) {
		return Boolean.parseBoolean((String) evt.getNewValue());
	}

	public static String stringValue(PropertyChangeEvent evt) {
		return (String) evt.getNewValue();
	}

}
