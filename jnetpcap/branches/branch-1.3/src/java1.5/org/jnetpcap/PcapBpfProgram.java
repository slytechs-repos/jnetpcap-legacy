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
package org.jnetpcap;

import java.nio.ByteBuffer;

// TODO: Auto-generated Javadoc
/**
 * The Class PcapBpfProgram.
 */
public class PcapBpfProgram {

	/**
	 * Inits the i ds.
	 */
	private native static void initIDs();

	static {
		/*
		 * Touch Pcap class. PcapBpfProgram JNI jfieldID tables are loaded during
		 * Pcap class static intialization process. Make sure Pcap loaded before us,
		 * otherwise we could get UnsatisfiedLinkError from JNI runtime if we're
		 * invoked before Pcap class.
		 */
		try {
			Class.forName("org.jnetpcap.Pcap");
			initIDs();
		} catch (ClassNotFoundException e) {
			// Empty on purpose
		}
	}

	/** The physical. */
	private volatile long physical = 0;

	/** The buffer. */
	private ByteBuffer buffer;

	/**
	 * Instantiates a new pcap bpf program.
	 */
	public PcapBpfProgram() {
		initPeer();
		buffer = null;
	}

	/**
	 * Inits the peer.
	 */
	private native void initPeer();

	/**
	 * Instantiates a new pcap bpf program.
	 * 
	 * @param instructions
	 *          the instructions
	 */
	public PcapBpfProgram(byte[] instructions) {
		buffer = null;

		if (instructions == null) {
			throw new NullPointerException("BPF instruction array is null");
		}

		if (instructions.length % 8 != 0) {
			throw new IllegalArgumentException(
			    "Invalid BPF instruction buffer length. Must be a multiple of 8");
		}

		if (instructions.length == 0) {
			throw new IllegalArgumentException("BPF instruction array is empty");
		}

		initPeer();

		/*
		 * Allocate bpf_program structure in native memory and copy the byte array
		 */
		initFromArray(instructions);
	}

	/**
	 * Instantiates a new pcap bpf program.
	 * 
	 * @param instructions
	 *          the instructions
	 */
	public PcapBpfProgram(ByteBuffer instructions) {
		if (instructions == null) {
			throw new NullPointerException("BPF instruction buffer is null");
		}

		int len = instructions.limit() - instructions.position();

		if (len % 8 != 0) {
			throw new IllegalArgumentException(
			    "Invalid BPF instruction buffer length. Must be a multiple of 8");
		}

		if (len == 0) {
			throw new IllegalArgumentException("BPF instruction array is empty");
		}

		initPeer();

		/*
		 * Allocate bpf_program structure in native memory and copy the buffer
		 */
		if (instructions.isDirect() == false) {
			initFromArray(instructions.array());
		} else {
			initFromBuffer(instructions);
			/*
			 * We need to make sure we keep a reference to the buffer so it doesn't
			 * get GCed since we're referencing its memory from peered bpf_program
			 * structure.
			 */
			buffer = instructions;
		}
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#finalize()
	 */
	@Override
  protected void finalize() {

		if (physical != 0) {
			cleanup();
		}
	}

	/**
	 * Cleanup.
	 */
	private native void cleanup();

	/**
	 * Inits the from array.
	 * 
	 * @param array
	 *          the array
	 */
	private void initFromArray(byte[] array) {
		buffer = ByteBuffer.allocateDirect(array.length);
		buffer.put(array);

		initFromBuffer(buffer);
	}

	/**
	 * Inits the from buffer.
	 * 
	 * @param buffer
	 *          the buffer
	 */
	private native void initFromBuffer(ByteBuffer buffer);

	/**
	 * Gets the instruction count.
	 * 
	 * @return the instruction count
	 */
	public native int getInstructionCount();

	/**
	 * Gets the instruction.
	 * 
	 * @param index
	 *          the index
	 * @return the instruction
	 */
	public native long getInstruction(int index);

	/**
	 * To long array.
	 * 
	 * @return the long[]
	 */
	public long[] toLongArray() {
		final int count = getInstructionCount();
		final long[] inst = new long[count];

		for (int i = 0; i < count; i++) {
			inst[i] = getInstruction(i);
		}

		return inst;
	}
}
