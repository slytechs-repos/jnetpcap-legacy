/**
 * Copyright (C) 2009 Sly Technologies, Inc.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package org.jnetpcap.nap;

import org.jnetpcap.nio.JMemory;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 *
 */
public class NapBlock extends JMemory {
	
	public static class Record extends Nap.Record {
		
	}
	
	private static class State extends JMemory {
		
		private final NapBlock parent;

	  public State(NapBlock parent) {
		  super(POINTER);
			this.parent = parent;
	  }
	  
	  private native void allocBlock(Nap nap, NapBlock header);
	  private native void cleanup(NapBlock header);

		/* (non-Javadoc)
     * @see org.jnetpcap.nio.JMemory#finalize()
     */
    @Override
    protected void finalize() {
    	cleanup(parent);
    }
	}
	
	private final State state = new State(this);
	private final Nap nap;

	/**
   * @param type
   */
  public NapBlock(Nap nap) {
	  super(POINTER);
		this.nap = nap;
	  
	  state.allocBlock(nap, this);
  }

}
