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
package org.jnetpcap.packet;

import java.util.Formatter;

import org.jnetpcap.nio.JStruct;

/**
 * A unique key that identifies a flow of related packets.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JFlowKey
    extends JStruct {

	public static final int FLAG_REVERSABLE = 0x00000001;

	/**
	 * MACRO used in native code
	 */
	@SuppressWarnings("unused")
	private static final int FLOW_KEY_PAIR_COUNT = 3;

	public final static String STRUCT_NAME = "flow_key_t";

	public native static int sizeof();

	/**
	 * @param structName
	 * @param type
	 */
	public JFlowKey() {
		super(STRUCT_NAME, Type.POINTER);
	}

	/**
	 * @param structName
	 * @param type
	 */
	public JFlowKey(Type type) {
		super(STRUCT_NAME, type);
	}

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
	 * @return
	 */
	public native int getFlags();

	/**
	 * Retrieves bitmap of headers that are part of this key. Each bit within the
	 * returned bitmap represents a different header ID.
	 * 
	 * @return bitmap of headers that have contributed atleast one key pair
	 */
	public native long getHeaderMap();

	public native int getId(int index);
	
	public int[] getIds() {
		int[] ids = new int[getPairCount()];
		
		for (int i = 0; i < ids.length; i ++) {
			ids[i] = getId(i);
		}
		
		return ids;
	}


	public native long getPair(int index, boolean reversePairs);
	
	public long[] getPairs() {
		long[] pairs = new long[getPairCount()];
		
		for (int i = 0; i < pairs.length; i ++) {
			pairs[i] = getPair(i, false);
		}
		
		return pairs;
	}

	public native int getPairCount();

	public native int getPairP1(int index, boolean reversePairs);
	
	public native int getPairP2(int index, boolean reversePairs);

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public native int hashCode();

	/**
	 * Compares the flow keys and returns the direction in which the match
	 * occured. Forward or reverse.
	 * 
	 * @param key
	 *          key to compare against this key
	 * @return 0 means key's don't match, 1 keys matched in forward direction and
	 *         -1 means matched in reverse direction.
	 */
	public native int match(JFlowKey key);

	protected int peer(JPacket.State peer) {

		/*
		 * Flowkey structure is always at the start of packet_state_t.
		 */
		return super.peer(peer);
	}

	public String toDebugString() {
		Formatter out = new Formatter();

		out.format("[count=%d, map=0x%x, hash=0x%x]", getPairCount(),
		    getHeaderMap(), hashCode());

		return out.toString();
	}
}
