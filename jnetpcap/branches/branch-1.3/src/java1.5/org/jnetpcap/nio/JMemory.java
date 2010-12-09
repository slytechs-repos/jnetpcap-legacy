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
package org.jnetpcap.nio;

import java.nio.ByteBuffer;
import java.util.Properties;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PeeringException;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.util.Units;

// TODO: Auto-generated Javadoc
/**
 * The Class JMemory.
 */
public abstract class JMemory {

	/**
	 * The Enum Type.
	 */
	public enum Type {
		
		/** The POINTER. */
		POINTER
	}

	/** The direct memory. */
	private static long directMemory;

	/** The direct memory soft. */
	private static long directMemorySoft;

	/** The Constant JNETPCAP_LIBRARY_NAME. */
	public static final String JNETPCAP_LIBRARY_NAME = "jnetpcap";
	
	/** The Constant MAX_DIRECT_MEMORY_DEFAULT. */
	public static final long MAX_DIRECT_MEMORY_DEFAULT = 64 * Units.MEBIBYTE;

	/** The Constant POINTER. */
	public static final JMemory.Type POINTER = JMemory.Type.POINTER;

	/**
	 * Load the native library and initialize JNI method and class IDs.
	 */
	static {
		try {
			System.loadLibrary(JNETPCAP_LIBRARY_NAME);

			Pcap.isInjectSupported();

			initIDs();

			setMaxDirectMemorySize(maxDirectMemory());
			setSoftDirectMemorySize(softDirectMemory());

			Class.forName("org.jnetpcap.nio.JMemoryReference");

		} catch (Exception e) {
			System.err.println(e.getClass().getName() + ": "
					+ e.getLocalizedMessage());
			throw new ExceptionInInitializerError(e);
		}
	}

	/**
	 * Allocate0.
	 * 
	 * @param size
	 *          the size
	 * @return the long
	 */
	private static native long allocate0(int size);

	/**
	 * Available direct memory.
	 * 
	 * @return the long
	 */
	public static native long availableDirectMemory();

	/**
	 * Inits the i ds.
	 */
	private static native void initIDs();

	/**
	 * Max direct memory.
	 * 
	 * @return the long
	 */

	public static long maxDirectMemory() {
		if (directMemory != 0) {
			return directMemory;
		}

		Properties p = System.getProperties();
		String s = p.getProperty("org.jnetsoft.nio.MaxDirectMemorySize");
		s = (s == null) ? p.getProperty("nio.MaxDirectMemorySize") : s;
		s = (s == null) ? p.getProperty("org.jnetsoft.nio.mx") : s;
		s = (s == null) ? p.getProperty("nio.mx") : s;

		if (s != null) {
			directMemory = parseSize(s); // process suffixes kb,mb,gb,tb
		}

		if (directMemory == 0) {
			directMemory = maxDirectoryMemoryDefault();
		}

		return directMemory;
	}

	/**
	 * Max direct memory breached.
	 */
	private static void maxDirectMemoryBreached() {
		DisposableGC.getDefault().invokeSystemGCAndWait();
	}

	/**
	 * Max directory memory default.
	 * 
	 * @return the long
	 */
	private static long maxDirectoryMemoryDefault() {
		long max = Runtime.getRuntime().maxMemory();

		if (max > MAX_DIRECT_MEMORY_DEFAULT) {
			max = MAX_DIRECT_MEMORY_DEFAULT;
		}

		return max;
	}

	/**
	 * Parses the size.
	 * 
	 * @param v
	 *          the v
	 * @return the long
	 */
	static long parseSize(String v) {
		v = v.trim().toLowerCase();
		long multiplier = 1;

		if (v.endsWith("tb")) {
			multiplier = Units.TEBIBYTE;
			v = v.substring(0, v.length() - 2);

		} else if (v.endsWith("gb")) {
			multiplier = Units.GIGIBYTE;
			v = v.substring(0, v.length() - 2);

		} else if (v.endsWith("mb")) {
			multiplier = Units.MEBIBYTE;
			v = v.substring(0, v.length() - 2);

		} else if (v.endsWith("kb")) {
			multiplier = Units.KIBIBYTE;
			v = v.substring(0, v.length() - 2);
		}

		final long size = Long.parseLong(v) * multiplier;

		return size;
	}

	/**
	 * Reserved direct memory.
	 * 
	 * @return the long
	 */
	public static native long reservedDirectMemory();

	/**
	 * Sets the max direct memory size.
	 * 
	 * @param size
	 *          the new max direct memory size
	 */
	private static native void setMaxDirectMemorySize(long size);

	/**
	 * Sets the soft direct memory size.
	 * 
	 * @param size
	 *          the new soft direct memory size
	 */
	private static native void setSoftDirectMemorySize(long size);

	/**
	 * Soft direct memory.
	 * 
	 * @return the long
	 */
	public static long softDirectMemory() {
		if (directMemorySoft != 0) {
			return directMemorySoft;
		}

		Properties p = System.getProperties();
		String s = p.getProperty("org.jnetsoft.nio.SoftDirectMemorySize");
		s = (s == null) ? p.getProperty("nio.SoftDirectMemorySize") : s;
		s = (s == null) ? p.getProperty("org.jnetsoft.nio.ms") : s;
		s = (s == null) ? p.getProperty("nio.ms") : s;

		if (s != null) {
			directMemorySoft = parseSize(s); // process suffixes kb,mb,gb,tb
		}

		if (directMemorySoft == 0) {
			directMemorySoft = maxDirectMemory();
		}

		return directMemorySoft;
	}

	/**
	 * Soft direct memory breached.
	 */
	private static void softDirectMemoryBreached() {
		DisposableGC.getDefault().invokeSystemGCWithMarker();
	}

	/**
	 * Total active allocated.
	 * 
	 * @return the long
	 */
	public static long totalActiveAllocated() {
		return totalAllocated() - totalDeAllocated();
	}

	/**
	 * Total allocate calls.
	 * 
	 * @return the long
	 */
	public native static long totalAllocateCalls();

	/**
	 * Total allocated.
	 * 
	 * @return the long
	 */
	public native static long totalAllocated();

	/**
	 * Total allocated segments0 to255 bytes.
	 * 
	 * @return the long
	 */
	public native static long totalAllocatedSegments0To255Bytes();

	/**
	 * Total allocated segments256 or above.
	 * 
	 * @return the long
	 */
	public native static long totalAllocatedSegments256OrAbove();

	/**
	 * Total de allocate calls.
	 * 
	 * @return the long
	 */
	public native static long totalDeAllocateCalls();

	/**
	 * Total de allocated.
	 * 
	 * @return the long
	 */
	public native static long totalDeAllocated();

	/**
	 * Transfer to0.
	 * 
	 * @param address
	 *          the address
	 * @param buffer
	 *          the buffer
	 * @param srcOffset
	 *          the src offset
	 * @param length
	 *          the length
	 * @param dstOffset
	 *          the dst offset
	 * @return the int
	 */
	protected static native int transferTo0(long address,
			byte[] buffer,
			int srcOffset,
			int length,
			int dstOffset);

	/** The keeper. */
	private Object keeper = null;

	/** The owner. */
	private boolean owner = false;

	/** The physical. */
	long physical;

	/** The ref. */
	private JMemoryReference ref = null;

	/** The size. */
	int size;

	/**
	 * Instantiates a new j memory.
	 * 
	 * @param peer
	 *          the peer
	 */
	public JMemory(ByteBuffer peer) {
		this(peer.limit() - peer.position());

		transferFrom(peer);
	}

	/**
	 * Instantiates a new j memory.
	 * 
	 * @param size
	 *          the size
	 */
	public JMemory(int size) {
		if (size <= 0) {
			throw new IllegalArgumentException("size must be greater than 0");
		}

		allocate(size);
	}

	/**
	 * Instantiates a new j memory.
	 * 
	 * @param src
	 *          the src
	 */
	public JMemory(JMemory src) {
		allocate(src.size);

		src.transferTo(this);
	}

	/**
	 * Instantiates a new j memory.
	 * 
	 * @param type
	 *          the type
	 */
	public JMemory(Type type) {
		if (type != Type.POINTER) {
			throw new IllegalArgumentException("Only POINTER types are supported");
		}
	}

	/**
	 * Allocate.
	 * 
	 * @param size
	 *          the size
	 * @return the long
	 */
	private long allocate(int size) {

		this.physical = allocate0(size);
		this.size = size;
		this.owner = true;
		this.keeper = this;

		this.ref = createReference(this.physical, size);

		return physical;
	}

	/**
	 * Check.
	 * 
	 * @throws IllegalStateException
	 *           the illegal state exception
	 */
	public void check() throws IllegalStateException {
		if (physical == 0) {
			throw new IllegalStateException(
					"peered object not synchronized with native structure");
		}
	}

	/**
	 * Check.
	 * 
	 * @param index
	 *          the index
	 * @param len
	 *          the len
	 * @param address
	 *          the address
	 * @return the int
	 */
	private final int check(int index, int len, long address) {
		if (address == 0L) {
			throw new NullPointerException();
		}

		if (index < 0 || index + len > size) {
			throw new IndexOutOfBoundsException(
					String.format("index=%d, len=%d, size=%d", index, len, size));
		}

		return index;
	}

	/**
	 * Cleanup.
	 */
	protected void cleanup() {
		if (ref != null) {
			this.ref.dispose();
			this.ref.remove();
			this.ref = null;
		}
		this.owner = false;
		this.keeper = null;
		this.physical = 0L;
		this.size = 0;
	}

	/**
	 * Creates the reference.
	 * 
	 * @param address
	 *          the address
	 * @param size
	 *          the size
	 * @return the j memory reference
	 */
	protected JMemoryReference createReference(final long address, long size) {
		return new JMemoryReference(this, address, size);
	}

	/**
	 * Checks if is initialized.
	 * 
	 * @return true, if is initialized
	 */
	public boolean isInitialized() {
		return physical != 0;
	}

	/**
	 * Checks if is j memory based owner.
	 * 
	 * @return true, if is j memory based owner
	 */
	public boolean isJMemoryBasedOwner() {
		return physical != 0 && (owner || keeper instanceof JMemory);
	}

	/**
	 * Checks if is the owner.
	 * 
	 * @return the owner
	 */
	public final boolean isOwner() {
		return this.owner;
	}

	/**
	 * Peer.
	 * 
	 * @param peer
	 *          the peer
	 * @return the int
	 * @throws PeeringException
	 *           the peering exception
	 */
	protected native int peer(ByteBuffer peer) throws PeeringException;

	/**
	 * Peer.
	 * 
	 * @param peer
	 *          the peer
	 * @return the int
	 */
	protected int peer(JMemory peer) {
		return peer(peer, 0, peer.size);
	}

	/**
	 * Peer.
	 * 
	 * @param peer
	 *          the peer
	 * @param offset
	 *          the offset
	 * @param length
	 *          the length
	 * @return the int
	 * @throws IndexOutOfBoundsException
	 *           the index out of bounds exception
	 */
	protected int peer(JMemory peer, int offset, int length)
			throws IndexOutOfBoundsException {

		if (offset < 0 || length < 0 || offset + length > peer.size) {
			throw new IndexOutOfBoundsException("Invalid [" + offset + ","
					+ (offset + length) + "," + length + ") range.");
		}

		return peer0(peer.physical + offset, length, peer.keeper);
	}

	/**
	 * Peer0.
	 * 
	 * @param peerAddress
	 *          the peer address
	 * @param length
	 *          the length
	 * @param keeper
	 *          the keeper
	 * @return the int
	 * @throws IndexOutOfBoundsException
	 *           the index out of bounds exception
	 */
	private int peer0(long peerAddress, int length, Object keeper)
			throws IndexOutOfBoundsException {

		if (peerAddress != this.physical) {
			cleanup();
		}

		this.physical = peerAddress;
		this.size = length;

		/**
		 * For specific reasons, we can never be the owner of the peered structure.
		 * The owner should remain the object that initially created or was created
		 * to manage the physical memory. The reasons are as follows:
		 * <ul>
		 * <li>Memory could be a revolving buffer
		 * <li>Memory allocation could have been complex with sub structures that
		 * need to be deallocated
		 * <li>The src object may have been passed around and references stored to
		 * it elsewhere. If we are GCed before src and we free up the memory the
		 * original src object would become unstable
		 * </ul>
		 */

		this.keeper = keeper;

		return size;
	}

	/**
	 * Sets the size.
	 * 
	 * @param size
	 *          the new size
	 */
	public void setSize(int size) {
		if (size > this.size) {
			throw new IllegalArgumentException(
					String
							.format("size (%d) parameter must be less then buffer size (%d)",
									size,
									this.size));
		}

		if (size < 0) {
			throw new IllegalArgumentException("negative size parameter");
		}

		this.size = size;
	}

	/**
	 * Sets the size0.
	 * 
	 * @param size
	 *          the new size0
	 */
	private void setSize0(int size) {
		this.size = size;
	}

	/**
	 * Size.
	 * 
	 * @return the int
	 */
	public int size() {
		if (isInitialized() == false) {
			throw new NullPointerException("jmemory not initialized");
		}

		return size;
	}

	/**
	 * To debug string.
	 * 
	 * @return the string
	 */
	public String toDebugString() {
		StringBuilder b = new StringBuilder();

		b.append("JMemory: JMemory@").append(Long.toHexString(physical))
				.append(getClass().toString()).append(": ");
		b.append("size=").append(size).append(" bytes");
		if (!owner) {
			b.append("\n");
			b.append("JMemory: owner=").append((keeper == null) ? "null" : keeper
					.getClass().getName().replaceAll("org.jnetpcap.", ""));
			b.append(".class");
			if (keeper instanceof JMemory) {
				JMemory k = (JMemory) keeper;
				b.append("(size=").append(k.size);
				b.append("/offset=").append(this.physical - k.physical);
				b.append(')');
			}
		} else {
			b.append("\n").append("JMemory: isOwner=").append(owner);
		}

		return b.toString();
	}

	/**
	 * To hexdump.
	 * 
	 * @return the string
	 */
	public String toHexdump() {
		JBuffer b = new JBuffer(Type.POINTER);
		b.peer(this);

		return FormatUtils.hexdumpCombined(b.getByteArray(0, size),
				0,
				0,
				true,
				true,
				true);
	}

	/**
	 * To hexdump.
	 * 
	 * @param length
	 *          the length
	 * @param address
	 *          the address
	 * @param text
	 *          the text
	 * @param data
	 *          the data
	 * @return the string
	 */
	public String toHexdump(int length,
			boolean address,
			boolean text,
			boolean data) {
		length = (length < size) ? length : size;
		JBuffer b = new JBuffer(Type.POINTER);
		b.peer(this);

		return FormatUtils.hexdumpCombined(b.getByteArray(0, length),
				0,
				0,
				address,
				text,
				data);
	}

	/**
	 * Transfer from.
	 * 
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	protected int transferFrom(byte[] buffer) {
		return transferFrom(buffer, 0, buffer.length, 0);
	}

	/**
	 * Transfer from.
	 * 
	 * @param buffer
	 *          the buffer
	 * @param srcOffset
	 *          the src offset
	 * @param length
	 *          the length
	 * @param dstOffset
	 *          the dst offset
	 * @return the int
	 */
	protected native int transferFrom(byte[] buffer,
			int srcOffset,
			int length,
			int dstOffset);

	/**
	 * Transfer from.
	 * 
	 * @param src
	 *          the src
	 * @return the int
	 */
	protected int transferFrom(ByteBuffer src) {
		return transferFrom(src, 0);
	}

	/**
	 * Transfer from.
	 * 
	 * @param src
	 *          the src
	 * @param dstOffset
	 *          the dst offset
	 * @return the int
	 */
	protected int transferFrom(ByteBuffer src, int dstOffset) {
		if (src.isDirect()) {
			return transferFromDirect(src, 0);
		} else {
			return transferFrom(src.array(),
					src.position(),
					src.limit() - src.position(),
					0);
		}
	}

	/**
	 * Transfer from direct.
	 * 
	 * @param src
	 *          the src
	 * @param dstOffset
	 *          the dst offset
	 * @return the int
	 */
	protected native int transferFromDirect(ByteBuffer src, int dstOffset);

	/**
	 * Transfer ownership.
	 * 
	 * @param memory
	 *          the memory
	 * @return true, if successful
	 */
	protected boolean transferOwnership(JMemory memory) {
		if (!memory.owner || this.physical == 0 || this.physical != memory.physical) {
			return false;
		}

		memory.owner = false;
		this.owner = true;
		this.keeper = null; // Release any kept references

		if (this.ref != null) {
			throw new IllegalStateException(
					"Can not transfer ownership when already own memory");
		}
		this.ref = createReference(memory.ref.address, memory.ref.size);

		memory.ref.remove();
		memory.ref = null;

		return true;
	}

	/**
	 * Transfer to.
	 * 
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	protected int transferTo(byte[] buffer) {

		return transferTo(buffer, 0, buffer.length, 0);
	}

	/**
	 * Transfer to.
	 * 
	 * @param buffer
	 *          the buffer
	 * @param srcOffset
	 *          the src offset
	 * @param length
	 *          the length
	 * @param dstOffset
	 *          the dst offset
	 * @return the int
	 */
	protected int transferTo(byte[] buffer,
			int srcOffset,
			int length,
			int dstOffset) {

		if (buffer == null) {
			throw new NullPointerException();
		}

		if (dstOffset < 0 || dstOffset + length > buffer.length) {
			throw new ArrayIndexOutOfBoundsException();
		}

		return transferTo0(physical,
				buffer,
				check(srcOffset, length, physical),
				length,
				dstOffset);
	}

	/**
	 * Transfer to.
	 * 
	 * @param dst
	 *          the dst
	 * @return the int
	 */
	public int transferTo(ByteBuffer dst) {
		return transferTo(dst, 0, size);
	}

	/**
	 * Transfer to.
	 * 
	 * @param dst
	 *          the dst
	 * @param srcOffset
	 *          the src offset
	 * @param length
	 *          the length
	 * @return the int
	 */
	public int transferTo(ByteBuffer dst, int srcOffset, int length) {
		if (dst.isDirect()) {
			return transferToDirect(dst, srcOffset, length);
		} else {
			int o = transferTo(dst.array(), srcOffset, length, dst.position());
			dst.position(dst.position() + o);

			return o;
		}
	}

	/**
	 * Transfer to.
	 * 
	 * @param dst
	 *          the dst
	 * @param srcOffset
	 *          the src offset
	 * @param length
	 *          the length
	 * @param dstOffset
	 *          the dst offset
	 * @return the int
	 */
	public int transferTo(JBuffer dst, int srcOffset, int length, int dstOffset) {
		return transferTo((JMemory) dst, srcOffset, length, dstOffset);
	}

	/**
	 * Transfer to.
	 * 
	 * @param dst
	 *          the dst
	 * @return the int
	 */
	protected int transferTo(JMemory dst) {
		return transferTo(dst, 0, size, 0);
	}

	/**
	 * Transfer to.
	 * 
	 * @param dst
	 *          the dst
	 * @param srcOffset
	 *          the src offset
	 * @param length
	 *          the length
	 * @param dstOffset
	 *          the dst offset
	 * @return the int
	 */
	protected native int transferTo(JMemory dst,
			int srcOffset,
			int length,
			int dstOffset);

	/**
	 * Transfer to direct.
	 * 
	 * @param dst
	 *          the dst
	 * @param srcOffset
	 *          the src offset
	 * @param length
	 *          the length
	 * @return the int
	 */
	private native int transferToDirect(ByteBuffer dst, int srcOffset, int length);
}
