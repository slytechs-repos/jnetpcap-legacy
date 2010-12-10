/*
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010 Sly Technologies, Inc.
 *
 * This file is part of jNetPcap.
 *
 * jNetPcap is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as 
 * published by the Free Software Foundation, either version 3 of 
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.jnetpcap.packet;

import java.util.Formatter;

import org.jnetpcap.nio.JStruct;

// TODO: Auto-generated Javadoc
/**
 * The Class JFlowKey.
 */
public class JFlowKey
    extends JStruct {

	/** The Constant FLAG_REVERSABLE. */
	public static final int FLAG_REVERSABLE = 0x00000001;

	/** The Constant FLOW_KEY_PAIR_COUNT. */
	private static final int FLOW_KEY_PAIR_COUNT = 3;

	/** The Constant STRUCT_NAME. */
	public final static String STRUCT_NAME = "flow_key_t";

	/**
	 * Sizeof.
	 * 
	 * @return the int
	 */
	public native static int sizeof();

	/**
	 * Instantiates a new j flow key.
	 */
	public JFlowKey() {
		super(STRUCT_NAME, Type.POINTER);
	}

	/**
	 * Instantiates a new j flow key.
	 * 
	 * @param type
	 *          the type
	 */
	public JFlowKey(Type type) {
		super(STRUCT_NAME, type);
	}

	/**
	 * Equal.
	 * 
	 * @param key
	 *          the key
	 * @return true, if successful
	 */
	public native boolean equal(JFlowKey key);

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof JFlowKey) {
			final JFlowKey key = (JFlowKey) obj;

			return this.equal(key);
		} else {
			return false;
		}
	}

	/**
	 * Gets the flags.
	 * 
	 * @return the flags
	 */
	public native int getFlags();

	/**
	 * Gets the header map.
	 * 
	 * @return the header map
	 */
	public native long getHeaderMap();

	/**
	 * Gets the id.
	 * 
	 * @param index
	 *          the index
	 * @return the id
	 */
	public native int getId(int index);
	
	/**
	 * Gets the ids.
	 * 
	 * @return the ids
	 */
	public int[] getIds() {
		int[] ids = new int[getPairCount()];
		
		for (int i = 0; i < ids.length; i ++) {
			ids[i] = getId(i);
		}
		
		return ids;
	}


	/**
	 * Gets the pair.
	 * 
	 * @param index
	 *          the index
	 * @param reversePairs
	 *          the reverse pairs
	 * @return the pair
	 */
	public native long getPair(int index, boolean reversePairs);
	
	/**
	 * Gets the pairs.
	 * 
	 * @return the pairs
	 */
	public long[] getPairs() {
		long[] pairs = new long[getPairCount()];
		
		for (int i = 0; i < pairs.length; i ++) {
			pairs[i] = getPair(i, false);
		}
		
		return pairs;
	}

	/**
	 * Gets the pair count.
	 * 
	 * @return the pair count
	 */
	public native int getPairCount();

	/**
	 * Gets the pair p1.
	 * 
	 * @param index
	 *          the index
	 * @param reversePairs
	 *          the reverse pairs
	 * @return the pair p1
	 */
	public native int getPairP1(int index, boolean reversePairs);
	
	/**
	 * Gets the pair p2.
	 * 
	 * @param index
	 *          the index
	 * @param reversePairs
	 *          the reverse pairs
	 * @return the pair p2
	 */
	public native int getPairP2(int index, boolean reversePairs);

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public native int hashCode();

	/**
	 * Match.
	 * 
	 * @param key
	 *          the key
	 * @return the int
	 */
	public native int match(JFlowKey key);

	/**
	 * Peer.
	 * 
	 * @param peer
	 *          the peer
	 * @return the int
	 */
	protected int peer(JPacket.State peer) {

		/*
		 * Flowkey structure is always at the start of packet_state_t.
		 */
		return super.peer(peer);
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.nio.JMemory#toDebugString()
	 */
	public String toDebugString() {
		Formatter out = new Formatter();

		out.format("[count=%d, map=0x%x, hash=0x%x]", getPairCount(),
		    getHeaderMap(), hashCode());

		return out.toString();
	}
}
