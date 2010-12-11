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

import org.jnetpcap.nio.JMemoryReference;
import org.jnetpcap.nio.JStruct;

// TODO: Auto-generated Javadoc
/**
 * The Class JScanner.
 */
public class JScanner extends JStruct {

	/** The count. */
	private static int count = 0;

	/** The Constant DEFAULT_BLOCKSIZE. */
	public static final int DEFAULT_BLOCKSIZE = 100 * 1024; // 100K

	/** The local scanners. */
	private static ThreadLocal<JScanner> localScanners =
			new ThreadLocal<JScanner>() {

				/*
				 * (non-Javadoc)
				 * 
				 * @see java.lang.ThreadLocal#initialValue()
				 */
				@Override
				protected JScanner initialValue() {
					return new JScanner();
				}

			};

	/** The Constant MAX_ENTRY_COUNT. */
	public static final int MAX_ENTRY_COUNT = 64;

	/** The Constant MAX_ID_COUNT. */
	public static final int MAX_ID_COUNT = 64;

	/** The Constant STRUCT_NAME. */
	public final static String STRUCT_NAME = "scanner_t";

	static {
		try {
			initIds();
		} catch (Exception e) {
			System.err.println("JScanner.static: error=" + e.toString());
			throw new ExceptionInInitializerError(e);
		}
	}

	/**
	 * Binding override.
	 * 
	 * @param id
	 *          the id
	 * @param enable
	 *          the enable
	 */
	public static void bindingOverride(int id, boolean enable) {
		if (enable) {
			JRegistry.setFlags(id, JRegistry.FLAG_OVERRIDE_BINDING);
		} else {
			JRegistry.clearFlags(id, JRegistry.FLAG_OVERRIDE_BINDING);
		}

		JPacket.getDefaultScanner().reloadAll();
	}

	/**
	 * Gets the thread local.
	 * 
	 * @return the thread local
	 */
	public static JScanner getThreadLocal() {
		// JScanner s = localScanners.get();
		// s.reloadAll();

		JScanner s = JPacket.getDefaultScanner();
		return s;
	}

	/**
	 * Shutdown.
	 */
	public static void shutdown() {

		localScanners.remove();
		localScanners = null;
	}

	/**
	 * Heuristic check.
	 * 
	 * @param id
	 *          the id
	 * @param enable
	 *          the enable
	 */
	public static void heuristicCheck(int id, boolean enable) {
		if (enable) {
			JRegistry.setFlags(id, JRegistry.FLAG_HEURISTIC_BINDING);
		} else {
			JRegistry.clearFlags(id, JRegistry.FLAG_HEURISTIC_BINDING);
		}

		JPacket.getDefaultScanner().reloadAll();
	}

	/**
	 * Heuristic post check.
	 * 
	 * @param id
	 *          the id
	 * @param enable
	 *          the enable
	 */
	public static void heuristicPostCheck(int id, boolean enable) {
		if (enable) {
			JRegistry.setFlags(id, JRegistry.FLAG_HEURISTIC_BINDING);
			JRegistry.clearFlags(id, JRegistry.FLAG_HEURISTIC_PRE_BINDING);
		} else {
			JRegistry.clearFlags(id, JRegistry.FLAG_HEURISTIC_BINDING);
			JRegistry.clearFlags(id, JRegistry.FLAG_HEURISTIC_PRE_BINDING);
		}

		JPacket.getDefaultScanner().reloadAll();
	}

	/**
	 * Heuristic pre check.
	 * 
	 * @param id
	 *          the id
	 * @param enable
	 *          the enable
	 */
	public static void heuristicPreCheck(int id, boolean enable) {
		if (enable) {
			JRegistry.setFlags(id, JRegistry.FLAG_HEURISTIC_BINDING);
			JRegistry.setFlags(id, JRegistry.FLAG_HEURISTIC_PRE_BINDING);
		} else {
			JRegistry.clearFlags(id, JRegistry.FLAG_HEURISTIC_BINDING);
			JRegistry.clearFlags(id, JRegistry.FLAG_HEURISTIC_PRE_BINDING);
		}

		JPacket.getDefaultScanner().reloadAll();
	}

	/**
	 * Inits the ids.
	 */
	private native static void initIds();

	/**
	 * Reset to defaults.
	 */
	public static void resetToDefaults() {
		for (int id = 0; id < JRegistry.MAX_ID_COUNT; id++) {
			JRegistry.clearFlags(id, 0xFFFFFFFF);
		}
	}

	/**
	 * Sizeof.
	 * 
	 * @return the int
	 */
	native static int sizeof();

	/**
	 * To bit mask.
	 * 
	 * @param ids
	 *          the ids
	 * @return the long
	 */
	private static long toBitMask(int... ids) {
		long o = 0L;
		for (int i = 0; i < ids.length; i++) {
			o |= (1L << i);
		}

		return o;
	}

	/**
	 * Instantiates a new j scanner.
	 */
	public JScanner() {
		this(DEFAULT_BLOCKSIZE);

		/*
		 * List<StackTraceElement> list = new
		 * ArrayList<StackTraceElement>(Arrays.asList(Thread.currentThread()
		 * .getStackTrace())); list.remove(0); list.remove(0);
		 * System.out.printf("%s:%s%n", toString(), list);
		 */
	}

	/**
	 * Instantiates a new j scanner.
	 * 
	 * @param blocksize
	 *          the blocksize
	 */
	public JScanner(int blocksize) {
		super(STRUCT_NAME + "#" + count++, blocksize + sizeof()); // Allocate memory

		init(new JScan());
		reloadAll();

		/*
		 * List<StackTraceElement> list = new
		 * ArrayList<StackTraceElement>(Arrays.asList(Thread.currentThread()
		 * .getStackTrace())); list.remove(0); list.remove(0);
		 * System.out.printf("%s:%s%n", toString(), list);
		 */
	}

	/**
	 * Gets the frame number.
	 * 
	 * @return the frame number
	 */
	public native long getFrameNumber();

	/**
	 * Inits the.
	 * 
	 * @param scan
	 *          the scan
	 */
	private native void init(JScan scan);

	/**
	 * Load flags.
	 * 
	 * @param flags
	 *          the flags
	 */
	private native void loadFlags(int[] flags);

	/**
	 * Load scanners.
	 * 
	 * @param scanners
	 *          the scanners
	 */
	private native void loadScanners(JHeaderScanner[] scanners);

	/**
	 * Reload all.
	 */
	public void reloadAll() {
		JHeaderScanner[] scanners = JRegistry.getHeaderScanners();

		for (int i = 0; i < scanners.length; i++) {
			if (scanners[i] == null) {
				continue;
			}

			if (scanners[i].hasBindings() || scanners[i].hasScanMethod()
					|| scanners[i].isDirect() == false) {
				// System.out.printf("%s, Downloading scanner [%s]\n", this,
				// scanners[i]);
			} else {
				scanners[i] = null;
			}
		}

		loadScanners(scanners);

		int[] flags = JRegistry.getAllFlags();
		loadFlags(flags);
	}

	/**
	 * Scan.
	 * 
	 * @param packet
	 *          the packet
	 * @param id
	 *          the id
	 * @return the int
	 */
	public int scan(JPacket packet, int id) {
		return scan(packet, id, packet.getPacketWirelen());
	}

	/**
	 * Scan.
	 * 
	 * @param packet
	 *          the packet
	 * @param id
	 *          the id
	 * @param wirelen
	 *          the wirelen
	 * @return the int
	 */
	public int scan(JPacket packet, int id, int wirelen) {
		final JPacket.State state = packet.getState();

		return scan(packet, state, id, wirelen);
	}

	/**
	 * Scan.
	 * 
	 * @param packet
	 *          the packet
	 * @param state
	 *          the state
	 * @param id
	 *          the id
	 * @param wirelen
	 *          the wirelen
	 * @return the int
	 */
	private native int scan(JPacket packet,
			JPacket.State state,
			int id,
			int wirelen);

	/**
	 * Sets the frame number.
	 * 
	 * @param frameNo
	 *          the new frame number
	 */
	public native void setFrameNumber(long frameNo);

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.JMemory#createReference(long)
	 */
	@Override
	protected JMemoryReference createReference(long address, long size) {
		return new JScannerReference(this, address, size);
	}
}
