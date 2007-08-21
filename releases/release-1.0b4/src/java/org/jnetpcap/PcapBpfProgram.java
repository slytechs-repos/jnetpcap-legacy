/**
 * Copyright (C) 2007 Sly Technologies, Inc. This library is free software; you
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
package org.jnetpcap;

import java.nio.ByteBuffer;

/**
 * <p>
 * Class peered with native <code>bpf_program</code> structure. Instance of a
 * compiled Berkley Packet Filter program. The program is an interpreted binary
 * byte program. Most modern unix and windows systems have a BPF interpreter
 * builtin and execute the code very efficiently, close to the source of the
 * capture and use the filter to permit or reject packets early.
 * </p>
 * <p>
 * <b>Special note:</b><br>
 * There also 2 private constructors which allow the object to be initialized in
 * Java space with a BPF program. The corresponding native C structures are
 * created and can be passed to <code>Pcap.setFilter</code> method. At this
 * time, the constructors are kept private for further testing. At some point
 * these private constructors will be made public and will allow outside filters
 * to be used with <em>Pcap</em> capture sessions.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class PcapBpfProgram {

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

	/**
	 * Native address of the bpf_program C structure
	 */
	@SuppressWarnings("unused")
	private volatile long physical = 0;

	/**
	 * Special constructor that allows creation of empty object ready for
	 * initialization. The object is only suitable for passing to Pcap.compile or
	 * Pcap.compileNoPcap which will initiliaze it. Using any of the getter
	 * methods before the PcapBpfProgram object is succesfully initialized will
	 * result in IllegalStateException being thrown.
	 * 
	 * @see Pcap#compile(PcapBpfProgram, String, int, int)
	 * @see Pcap#compileNoPcap(int, int, PcapBpfProgram, String, int, int)
	 */
	public PcapBpfProgram() {
		initPeer();
	}
	
	/**
	 * Allocates object's peered C structure bpf_program.
	 */
	private native void initPeer();

	@SuppressWarnings("unused")
	private PcapBpfProgram(byte[] instructions) {
		if (instructions == null) {
			throw new NullPointerException("BPF instruction array is null");
		}

		if (instructions.length % 8 != 0) {
			throw new IllegalArgumentException(
			    "Invalid BPF instruction byte[] length. Must be a multiple of 8");
		}

		if (instructions.length == 0) {
			throw new IllegalArgumentException("BPF instruction array is empty");
		}

		/*
		 * Allocate bpf_program structure in native memory and copy the byte array
		 */
		initFromArray(instructions);
	}

	@SuppressWarnings("unused")
	private PcapBpfProgram(ByteBuffer instructions) {
		if (instructions == null) {
			throw new NullPointerException("BPF instruction buffer is null");
		}

		int len = instructions.limit() - instructions.position();

		if (len % 8 != 0) {
			throw new IllegalArgumentException(
			    "Invalid BPF instruction byte[] length. Must be a multiple of 8");
		}

		if (len == 0) {
			throw new IllegalArgumentException("BPF instruction array is empty");
		}

		/*
		 * Allocate bpf_program structure in native memory and copy the buffer
		 */
		if (instructions.isDirect() == false) {
			initFromArray(instructions.array());
		} else {
			initFromBuffer(instructions, instructions.position(), len);
		}
	}

	/**
	 * Cleans up JNI resources and releases any unreleased BPF programs in native
	 * land.
	 */
	protected void finalize() {

		if (physical != 0) {
			cleanup();
		}
	}

	/**
	 * Cleans up the object, releasing any resource held at native JNI level.
	 */
	private native void cleanup();

	/**
	 * Allocates new bpf_program structure and enough space for code in the array
	 * and makes a copy.
	 * 
	 * @param array
	 *          bpf instruction array
	 */
	private native void initFromArray(byte[] array);

	/**
	 * Allocates new bpf_program structure and enough space for code in the buffer
	 * and makes a copy.
	 * 
	 * @param buffer
	 *          bpf instruction buffer
	 * @param start
	 *          start position within the buffer
	 * @param len
	 *          length to copy from the buffer
	 */
	private native void initFromBuffer(ByteBuffer buffer, int start, int len);

	/**
	 * Gets the exact number of BPF instructions within this program.
	 * 
	 * @return number of 8 byte instructions within this program
	 */
	public native int getInstructionCount();

	/**
	 * Retrieves a single BPF instruction which is 8 bytes long and is encoded
	 * into the long interger returned.
	 * 
	 * @param index
	 *          index of the instruction
	 * @return entire instruction
	 */
	public native long getInstruction(int index);

}
