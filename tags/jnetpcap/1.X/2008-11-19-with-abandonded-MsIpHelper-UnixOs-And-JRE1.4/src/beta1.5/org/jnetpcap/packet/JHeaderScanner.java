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

import org.jnetpcap.nio.JFunction;

/**
 * A header scanner, there is one per header, that is able to scan raw memory
 * buffer and determine the length of the header and the next header ID after
 * examining the current header's structure. The header scanner is bound to the
 * native direct scanner provided by the jNetPcap native implementation. The
 * header scanner can be overriden with a java implementation by simply
 * subclassing it and overriding the <code>getHeaderLength</code> and
 * <code>getNextHeader</code> methods. If either of the 2 types of methods are
 * overriden, then the user should also overriden the {@link #isDirect()} method
 * and return false to indicate that this is not a native direct scanner.
 * <p>
 * The header scanner is natively peered directly with the appropriate function
 * that performs the scan and determines the next protocol in chain of headers
 * found in the data buffer. Another words this class is peered using a function
 * pointer and dispatched appropriately when invoked to scan for length or next
 * header id.
 * </p>
 * <p>
 * Here is a typedef definition and the function pointer signature.
 * 
 * <pre>
 * typedef void (*native_protocol_func_t)(scan_t *scan);
 * </pre>
 * 
 * <b>Note</b> that scan_t structure is implemented by java class JScan which
 * is peered with that structure.
 * </p>
 * 
 * @see JScan
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JHeaderScanner
    extends JFunction {

	private static final String FUNCT_NAME = "scan_";

	private final int id;

	private final boolean nativeIsBound;
	
	static {
		JScanner.sizeof(); // Make sure JScanner initializes first
	}

	public JHeaderScanner(JProtocol protocol) throws UnregisteredScannerException {
		super(FUNCT_NAME + protocol.toString().toLowerCase());
		this.id = protocol.ID;

		bindNativeScanner(id);
		nativeIsBound = true;
	}

	private native void bindNativeScanner(int id)
	    throws UnregisteredScannerException;

	/**
	 * Checks if the scanner at the given ID is a direct or java scanner.
	 * 
	 * @param id
	 *          id of the protocol to check for native direct scanner
	 * @return true there is a native scanner for this id, otherwise false
	 */
	public boolean isDirect() {
		return nativeIsBound;
	}

	/**
	 * @return the id
	 */
	public final int getId() {
		return this.id;
	}

	private native void nativeScan(JScan scan);

	public int getHeaderLength(JPacket packet, int offset) {
		return 0;
	}

	public int getNextHeader(JPacket packet, int offset) {
		final JBinding[] bindings = JRegistry.getBindings(getId());

		for (final JBinding b : bindings) {
			if (b == null) {
				continue;
			}
			
			final int id = b.scanForNextHeader(packet, offset);
			if (id != JProtocol.PAYLOAD_ID) {
				return id;
			}
		}

		return JProtocol.PAYLOAD_ID;
	}

	protected void scanHeader(final JScan scan) {
		final JPacket packet = scan.scan_packet();
		final int offset = scan.scan_offset();
		final boolean lengthOverride =
		    (JRegistry.getFlags(id) & JRegistry.FLAG_OVERRIDE_LENGTH) != 0;
		final boolean bindOverride =
		    (JRegistry.getFlags(id) & JRegistry.FLAG_OVERRIDE_BINDING) != 0;

		if (!lengthOverride || !bindOverride) {
			nativeScan(scan);
		}

		if (lengthOverride) {
			int l = getHeaderLength(packet, offset);
			if (l > 0) {
				scan.scan_length(l);
			}
		}

		if (bindOverride || scan.scan_next_id() == JProtocol.PAYLOAD_ID) {
			scan.scan_next_id(getNextHeader(packet, offset));
		} else {
			return;
		}

	}
}
