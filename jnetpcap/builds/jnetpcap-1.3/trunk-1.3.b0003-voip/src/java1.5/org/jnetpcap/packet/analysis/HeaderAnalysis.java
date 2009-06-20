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
package org.jnetpcap.packet.analysis;


/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class HeaderAnalysis
    extends AbstractAnalysis<HeaderAnalysis, AnalyzerEvent> {
	
	@SuppressWarnings("unused")
  private final static String NAME = "Header";
	
	public enum Field implements JStructField {
		;
		private final int len;

		int offset;

		private Field() {
			this(4);
		}

		private Field(int len) {
			this.len = len;
		}

		public int length(int offset) {
			this.offset = offset;
			return this.len;
		}

		public final int offset() {
			return offset;
		}

	}

	/**
   * @param type
   * @param size
   */
  public HeaderAnalysis() {
	  super(Type.POINTER);
  }

	public boolean hasFieldErrors() {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Not implemented yet");
	}

	public boolean hasFieldWarnings() {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Not implemented yet");
	}

	public FieldAnalysis[] getFieldErrors() {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Not implemented yet");
	}

	public FieldAnalysis[] getFieldWarnings() {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Not implemented yet");
	}

}
