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
public class FieldAnalysis
    extends AbstractAnalysis<FieldAnalysis, AnalyzerEvent> {

	@SuppressWarnings("unused")
  private static final String NAME = "Field";
	
	@SuppressWarnings("unused")
  private enum Field implements JStructField {
	  ;

		/* (non-Javadoc)
     * @see org.jnetpcap.packet.analysis.AbstractAnalysis.JStructField#length(int)
     */
    public int length(int offset) {
	    // TODO Auto-generated method stub
	    throw new UnsupportedOperationException("Not implemented yet");
    }

		/* (non-Javadoc)
     * @see org.jnetpcap.util.Offset#offset()
     */
    public int offset() {
	    // TODO Auto-generated method stub
	    throw new UnsupportedOperationException("Not implemented yet");
    }
		
	}

	/**
   * @param type
   * @param size
   */
  public FieldAnalysis() {
	  super(Type.POINTER);
  }

	public String getFieldName() {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Not implemented yet");
	}

	/**
	 * @return
	 */
	public String getErrorMessage() {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Not implemented yet");
	}
}
