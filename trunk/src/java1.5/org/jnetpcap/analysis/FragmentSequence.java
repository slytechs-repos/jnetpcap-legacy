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
package org.jnetpcap.analysis;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.util.Timeout;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class FragmentSequence
    extends AbstractAnalysis<FragmentSequence, FragmentSequenceEvent> implements
    Timeout {

	public final static int FLAG_HAS_ALL_FRAGMENTS = 0x0001;

	public final static int FLAG_HAS_FIRST_FRAGMENT = 0x0002;

	public final static int FLAG_HAS_LAST_FRAGMENT = 0x0004;

	private static final String NAME = "Fragment Sequence";

	private static final String NICNAME = "Frame";

	private final FragmentSequenceAnalyzer analyzer;

	private int totalLength = -1;

	public enum Field implements AnalysisField {
		PACKET_SEQUENCE(0, REF),
		FLAGS(REF, 4),
		TIMEOUT(REF + 4, 8),
		LEN(REF + 12, 4),
		HASH(REF + 16, 4),
		LAST(REF + REF + 20, 0),
		;
		private final int len;
		private final int offset;
		private Field() {
			this(0, 4);
		}

		private Field(int offset, int len) {
			this.len = len;
			this.offset = offset;
		}

		public final int getLength() {
    	return this.len;
    }

		public final int getOffset() {
    	return this.offset;
    }
	}
	
	/**
	 * @param type
	 * @param size
	 */
	public FragmentSequence() {
		super(Type.POINTER, 0, NAME);

		this.analyzer = null;
	}
	
	/**
	 * @param size
	 */
	public FragmentSequence(int hash, FragmentSequenceAnalyzer analyzer) {
		super(Field.LAST.getOffset(), NAME);
		this.analyzer = analyzer;

		setPacketSequence(new LinkedList<JPacket>());
		setLen(0);
		setHash(hash);
	}
	
	private void setHash(int hash) {
		super.setInt(Field.HASH.getOffset(), hash);
	}

	/**
	 * @param packet
	 * @param offset
	 * @param length
	 */
	public void addFragment(JPacket packet, int offset, int length) {
		getPacketSequence().add(packet);
		
		setLen(getLen() + length);
	}


	@Override
  public int hashCode() {
		return super.getInt(Field.HASH.getOffset());
  }

	private int getFlags() {
		return super.getInt(Field.FLAGS.getOffset());
	}

	public int getLen() {
		return super.getInt(Field.LEN.getOffset());
	}

	@SuppressWarnings("unchecked")
	public List<JPacket> getPacketSequence() {
		return super.getObject(List.class, Field.PACKET_SEQUENCE.getOffset());
	}

	@Override
	public String getShortTitle() {
		return NICNAME;
	}

	@Override
	public String[] getText() {
		StringBuilder b = new StringBuilder();
		for (JPacket packet : getPacketSequence()) {
			if (b.length() != 0) {
				b.append(", ");
			}

			b.append("#").append(packet.getState().getFrameNumber());
		}
		// return b.toString();
		return null;
	}

	public long getTimeout() {
		return super.getLong(Field.TIMEOUT.getOffset());
	}

	public final int getTotalLength() {
  	return this.totalLength;
  }

	public boolean hasAllFragments() {
		return (getFlags() & FLAG_HAS_ALL_FRAGMENTS) > 0;
	}

	/**
   * @return
   */
  public boolean hasLastFragment() {
  	return (getFlags() & FLAG_HAS_LAST_FRAGMENT) > 0;
  }

	/**
	 * @return
	 */
	public boolean isEmpty() {
		return getPacketSequence().isEmpty();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.Timeout#isTimedout(long)
	 */
	public boolean isTimedout(long timeInMillis) {
		return getTimeout() < timeInMillis;
	}

	@Override
	public Iterator<JAnalysis> iterator() {
		return analyzer.generateInfo(this).iterator();
	}

	private void setFlags(int flags) {
		super.setInt(Field.FLAGS.getOffset(), flags);
	}

	public void setHasAllFragments(boolean state) {
		setFlags(getFlags() | FLAG_HAS_ALL_FRAGMENTS);
	}

	/**
   * @param tru
   */
  public void setHasFirstFragment(boolean state) {
  	if (state) {
  		setFlags(getFlags() | FLAG_HAS_FIRST_FRAGMENT);
  	} else {
  		setFlags(getFlags() & ~FLAG_HAS_FIRST_FRAGMENT);
  	}
  }

	/**
   * @param tru
   */
  public void setHasLastFragment(boolean state) {
  	if (state) {
  		setFlags(getFlags() | FLAG_HAS_LAST_FRAGMENT);
  	} else {
  		setFlags(getFlags() & ~FLAG_HAS_LAST_FRAGMENT);
  	}
  }

	public void setLen(int len) {
		super.setInt(Field.LEN.getOffset(), len);
	}
  
	private void setPacketSequence(List<JPacket> list) {
		super.setObject(Field.PACKET_SEQUENCE.getOffset(), list);
	}

	/**
	 * @param timeout
	 */
	public void setTimeout(long timeout) {
		super.setLong(Field.TIMEOUT.getOffset(), timeout);
	}

	public final void setTotalLength(int totalLength) {
  	this.totalLength = totalLength;
  }

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.Timeout#timeout()
	 */
	public void timeout() {
		analyzer.timeout(this);
	}

	/* (non-Javadoc)
   * @see java.lang.Comparable#compareTo(java.lang.Object)
   */
  public int compareTo(Timeout o) {
  	return o.equals(this) ? 0 : 1;
  }

}
