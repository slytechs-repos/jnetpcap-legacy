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

import java.nio.ByteBuffer;

import org.jnetpcap.JCaptureHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemoryPool.Block.Malloced;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JMemoryPacket
    extends JPacket {

	private final JMemoryHeader header = new JMemoryHeader();
		
	private static class JMemoryHeader implements JCaptureHeader {
		
		private int caplen;
		private int wirelen;
		private long nanos;
		private long seconds;
		private long inMillis;

		public int caplen() {
			return caplen;
		}

		public long nanos() {
			return nanos;
		}

		public long seconds() {
			return seconds;
		}

		public long timestampInMillis() {
			return inMillis;
		}
		
		public int wirelen() {
			return wirelen;
		}

		/**
     * @param caplen
     * @param nanos
     * @param seconds
     */
    public JMemoryHeader(int caplen, int wirelen, long nanos, long seconds) {
	    init(caplen, wirelen, nanos, seconds);
    }
    
    public JMemoryHeader() {
    	// Empty
    }
    
    public void init(int caplen, int wirelen, long nanos, long seconds) {
	    this.caplen = caplen;
	    this.wirelen = wirelen;
	    this.nanos = nanos;
	    this.seconds = seconds;
	    
			this.inMillis = seconds() * 1000 + nanos() / 1000000;
   	
    }

		public final int getWirelen() {
    	return this.wirelen;
    }

		public final void setWirelen(int wirelen) {
    	this.wirelen = wirelen;
    }

	};

	/**
	 * @param buffer
	 */
	public JMemoryPacket(byte[] buffer) {
		super(buffer.length, 0);
	}

	/**
	 * @param buffer
	 * @throws PeeringException 
	 */
	public JMemoryPacket(ByteBuffer buffer) throws PeeringException {
		super(Type.POINTER);
		
		peer(buffer);
	}

	/**
	 * @param buffer
	 */
	public JMemoryPacket(JBuffer buffer) {
		super(Type.POINTER);
		
		peer(buffer);
	}

	/**
	 * @param type
	 */
	public JMemoryPacket(Type type) {
		super(type);
	}

	/**
	 * @param size
	 */
	public JMemoryPacket(int size) {
		super(size, State.sizeof(DEFAULT_STATE_HEADER_COUNT));
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JPacket#getCaptureHeader()
	 */
	@Override
	public JCaptureHeader getCaptureHeader() {
		return this.header;
	}

	/* (non-Javadoc)
   * @see org.jnetpcap.packet.JPacket#getStateAndMemorySize()
   */
  @Override
  protected int getTotalSize() {
	  return super.size() + super.state.size();
  }

	public int transferTo(JPacket packet, int offset) {
		final Malloced buffer = packet.getMemoryBuffer(this.getTotalSize());
		
		packet.state.peerTo(buffer, offset, state.size());
		int o = state.transferTo(packet.state);
		
		packet.peer(this, offset, size());
		o += this.transferTo(buffer, 0, size(), offset + o);
		
		final JCaptureHeader h = packet.getCaptureHeader();
		header.init(h.caplen(), h.wirelen(), h.seconds(), h.nanos());
		
		return o;
	}

}
