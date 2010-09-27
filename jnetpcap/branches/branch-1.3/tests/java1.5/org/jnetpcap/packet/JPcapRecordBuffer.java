/**
 * Copyright (C) 2010 Sly Technologies, Inc.
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
package org.jnetpcap.packet;

import java.nio.ByteOrder;

import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;

public class JPcapRecordBuffer
    extends
    JBuffer
    implements
    JPcapRecordIterable {

	private final int start = 4;

	private int limit;

	private int position = start;

	private final int capacity;

	private int count = 0;
	
	private Record[] records;
	
	/**
	 * @param size
	 */
	public JPcapRecordBuffer(int size) {
		super(size);
		this.capacity = size;
		this.limit = capacity;
		
		this.order(ByteOrder.nativeOrder());
	}

	public int getPacketRecordCount() {
		return count;
	}

	private void setPacketRecordCount(int value) {
		super.setUInt(0, value);

		count = value;
	}

	public void append(PcapHeader header, JBuffer packet) {
		header.transferTo(this, position);
		position += header.sizeof();

		packet.transferTo(this, 0, packet.size(), position);
		position += packet.size();

		count++;
	}
	
	public void close() {
		limit = position;
		position = start;
		
		this.setInt(0, count);
		
		JBuffer b = new JBuffer(limit);
		b.order(ByteOrder.nativeOrder());
		this.transferTo(b, 0, limit, 0);
		
		// Resize to smaller
		this.peer(b, 0, b.size());
		
		records = new Record[count];

		Iterator it = iterator();
		for (int i = 0; i < count && it.hasNext(); i ++) {
			records[i] = new Record();
			records[i].header = new PcapHeader(JMemory.POINTER);
			records[i].packet = new JBuffer(JMemory.POINTER);
			
			it.next(records[i].header, records[i].packet);
		}
	}
	
	public static class Record {
		public PcapHeader header;
		public JBuffer packet;
	}

	public class Iterator implements java.util.Iterator<JPcapRecordBuffer.Record> {
		private int offset = start;
		private int index = 0;

		/* (non-Javadoc)
     * @see java.util.Iterator#hasNext()
     */
    public boolean hasNext() {
      return index < count;
    }

		/* (non-Javadoc)
     * @see java.util.Iterator#next()
     */
    public JPcapRecordBuffer.Record next() {
      return records[index ++];
    }
    
    final int PCAP_HEADER_SIZEOF = PcapHeader.sizeof();
    public void next(PcapHeader header, JBuffer packet) {
      offset += header.peerTo(JPcapRecordBuffer.this, offset);
//      offset += PCAP_HEADER_SIZEOF;
      
      offset += packet.peer(JPcapRecordBuffer.this, offset, header.caplen());
//      offset += header.caplen();
      index ++;
   	
    }

		/* (non-Javadoc)
     * @see java.util.Iterator#remove()
     */
    public void remove() {
      throw new UnsupportedOperationException("optional method not implemented");
    }
    
    public void reset() {
    	offset = start;
    	index = 0;
    }

		/**
     * @return
     */
    public long getPacketRecordCount() {
	    return count;
    }
		
	}

	/* (non-Javadoc)
   * @see org.jnetpcap.packet.JPcapRecordIterable#iterator()
   */
  public JPcapRecordBuffer.Iterator iterator() {
    return new JPcapRecordBuffer.Iterator();
  }
  
  public String toString() {
  	return "packets = " + count;
  }
}