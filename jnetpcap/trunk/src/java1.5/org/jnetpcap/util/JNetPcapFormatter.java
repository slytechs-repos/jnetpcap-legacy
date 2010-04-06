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

import java.util.logging.Formatter;
import java.util.logging.LogRecord;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JNetPcapFormatter
    extends Formatter {

	/**
	 * 
	 */
	public JNetPcapFormatter() {
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.util.logging.Formatter#format(java.util.logging.LogRecord)
	 */
	@Override
	public String format(LogRecord record) {
		final String msg =
		    String.format(record.getMessage(), record.getParameters());
		record.getLoggerName().split("\\.");
		String prefix = prefix(record);

		Throwable thrown = record.getThrown();
		String error = "";
		if (thrown != null) {
			StringBuilder b = new StringBuilder();
			String ex = thrown.getClass().getCanonicalName() + ":";
//			b.append(prefix).append(" ");
			b.append(ex).append(" ");
			b.append(thrown.getMessage()).append("\n");
			
			for (StackTraceElement e : thrown.getStackTrace()) {
				b.append(ex).append(" ");
				b.append(e.toString()).append("\n");
			}

			error = b.toString();
		}

		return String.format(prefix + " %s\n%s", msg, error);
	}

	private String prefix(LogRecord record) {
		String[] c = record.getLoggerName().split("\\.");

		return String.format("%s:%s:", record.getLevel().toString(),
		    c[c.length - 1], record.getSourceMethodName());
	}
}
