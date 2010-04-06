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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Formatter;
import java.util.List;

import org.jnetpcap.nio.JFunction;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.packet.structure.AnnotatedHeaderLengthMethod;
import org.jnetpcap.packet.structure.AnnotatedScannerMethod;
import org.jnetpcap.protocol.JProtocol;

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
    extends
    JFunction {

	private static final String FUNCT_NAME = "scan_";

	static {
		JScanner.sizeof(); // Make sure JScanner initializes first
	}

	private JBinding[] bindings = null;

	private final List<JBinding> bindingsList = new ArrayList<JBinding>();

	private final int id;

	private AnnotatedHeaderLengthMethod[] lengthMethods;

	private AnnotatedScannerMethod scannerMethod;

	private final JProtocol protocol;

	private boolean needJProtocolInitialization;

	public JHeaderScanner(final Class<? extends JHeader> c) {
		super("java header scanner");

		this.protocol = null;
		this.needJProtocolInitialization = false;
		this.id = JRegistry.lookupId(c);

		this.lengthMethods = AnnotatedHeaderLengthMethod.inspectClass(c);

		if (AnnotatedScannerMethod.inspectClass(c).length != 0) {
			this.scannerMethod = AnnotatedScannerMethod.inspectClass(c)[0];
		} else {
			this.scannerMethod = null;
		}
	}

	/**
	 * A java scanner for headers out of a native packet buffer. This constructor
	 * allows a custom header scanner to be implemented and registered with
	 * JRegistry. The packet scanner, JScanner, uses builtin native scanners to
	 * scan packet buffers but also allows custom java scanners to override or
	 * provide additional header scanners. Any new protocol header being added to
	 * jNetPcap library of protocols, that is not officially released with this
	 * API, will have to provide its own custom header scanner.
	 * 
	 * @param protocol
	 *          core protocol constant for which to override its default native
	 *          header scanner
	 */
	public JHeaderScanner(final JProtocol protocol) {
		super(FUNCT_NAME + protocol.toString().toLowerCase());
		this.protocol = protocol;
		this.id = protocol.getId();
		this.needJProtocolInitialization = true;

		bindNativeScanner(this.id);
	}

	private void initFromJProtocol(final JProtocol protocol) {

		final Class<? extends JHeader> clazz = protocol.getHeaderClass();

		this.lengthMethods = AnnotatedHeaderLengthMethod.inspectClass(clazz);

		if (AnnotatedScannerMethod.inspectClass(clazz).length != 0) {
			this.scannerMethod = AnnotatedScannerMethod.inspectClass(clazz)[0];
		} else {
			this.scannerMethod = null;
		}

		this.needJProtocolInitialization = false;
	}

	private AnnotatedHeaderLengthMethod getLengthMethod(
	    final HeaderLength.Type type) {
		if (this.needJProtocolInitialization) {
			initFromJProtocol(this.protocol);
		}
		return this.lengthMethods[type.ordinal()];
	}

	private AnnotatedScannerMethod getScannerMethod() {
		if (this.needJProtocolInitialization) {
			initFromJProtocol(this.protocol);
		}
		return this.scannerMethod;

	}

	public boolean addBindings(final JBinding... bindings) {
		this.bindings = null;

		return this.bindingsList.addAll(Arrays.asList(bindings));
	}

	private native void bindNativeScanner(int id);

	public void clearBindings() {
		this.bindings = null;
		this.bindingsList.clear();
	}

	public boolean hasBindings() {
		return this.bindingsList.isEmpty() == false;
	}

	/**
	 * @return
	 */
	public JBinding[] getBindings() {
		if (this.bindings == null) {
			this.bindings =
			    this.bindingsList.toArray(new JBinding[this.bindingsList.size()]);
		}

		return this.bindings;
	}

	/**
	 * Returns the length of the header this scanner is registered for
	 * 
	 * @param packet
	 *          the packet object this header is bound to
	 * @param offset
	 *          offset into the packet buffer in bytes of the start of this header
	 * @return length of the header or 0 if this header is not found in the packet
	 *         buffer
	 */
	public int getHeaderLength(final JPacket packet, final int offset) {
		return getLengthMethod(HeaderLength.Type.HEADER).getHeaderLength(packet,
		    offset);
	}

	public int getPrefixLength(final JPacket packet, final int offset) {
		return (getLengthMethod(HeaderLength.Type.PREFIX) == null) ? 0
		    : getLengthMethod(HeaderLength.Type.PREFIX).getHeaderLength(packet,
		        offset);
	}

	public int getGapLength(final JPacket packet, final int offset) {
		return (getLengthMethod(HeaderLength.Type.GAP) == null) ? 0
		    : getLengthMethod(HeaderLength.Type.GAP)
		        .getHeaderLength(packet, offset);
	}

	public int getPayloadLength(final JPacket packet, final int offset) {
		return (getLengthMethod(HeaderLength.Type.PAYLOAD) == null) ? 0
		    : getLengthMethod(HeaderLength.Type.PAYLOAD).getHeaderLength(packet,
		        offset);
	}

	public int getPostfixLength(final JPacket packet, final int offset) {
		return (getLengthMethod(HeaderLength.Type.POSTFIX) == null) ? 0
		    : getLengthMethod(HeaderLength.Type.POSTFIX).getHeaderLength(packet,
		        offset);
	}

	/**
	 * Gets the protocol header's numerical ID as assigned by JRegistry
	 * 
	 * @return the id numerical ID of the header
	 */
	public final int getId() {
		return this.id;
	}

	/**
	 * Checks if the scanner at the given ID is a direct or java scanner.
	 * 
	 * @return true there is a native scanner for this id, otherwise false
	 */
	public boolean isDirect() {
		return super.isInitialized() && (getScannerMethod() == null);
	}

	/**
	 * The native scanner must be initialized before this method can be called
	 * using bindNativeScanner.
	 * 
	 * @param scan
	 *          a work structure
	 */
	private native void nativeScan(JScan scan);

	public boolean removeBindings(final JBinding... bindings) {
		this.bindings = null;

		return this.bindingsList.removeAll(Arrays.asList(bindings));
	}

	/**
	 * Calculates the next header in sequence of headers within the packet buffer
	 * 
	 * @param packet
	 *          the packet object this header is bound to
	 * @param offset
	 *          offset into the packet buffer in bytes of the start of this header
	 * @return numerical ID of the next header as assigned by JRegistry
	 */
	public int scanAllBindings(final JPacket packet, final int offset) {
		for (final JBinding b : getBindings()) {
			if (b == null) {
				continue;
			}

			if (b.isBound(packet, offset)) {
				return b.getSourceId();
			}
		}

		return JProtocol.PAYLOAD_ID;
	}

	/**
	 * The main method that this header scanner is called on by the packet
	 * scanner, typically from native user space
	 * 
	 * @param scan
	 *          scan state structure that is used to pass around state both in
	 *          java and native user space
	 */
	protected void scanHeader(final JScan scan) {

		if (getScannerMethod() != null) {
			getScannerMethod().scan(scan);

		} else if (isDirect()) {
			nativeScan(scan);

		} else {
			/*
			 * Record this header's length
			 */
			final JPacket packet = scan.scan_packet();
			final int offset = scan.scan_offset();

			setAllLengths(scan, packet, offset);
		}

		if (scan.scan_length() == 0) {
			return;
		}

		if (scan.scan_next_id() == JProtocol.PAYLOAD_ID) {
			/*
			 * Because java bindings we are about to invoke, rely on the the current
			 * header being already recorded in packet_state_t structure, we call on
			 * the record_header method menually. Here are some major effects as a
			 * result of this call:
			 */
			/* 1 - payload is calculated if not set; */
			/* 2 - protocol record properties are truncated from their theoretical; */
			/*
			 * 3 - header state pointer is advanced to the next structure in the
			 * packet->header array;
			 */
			/* 4 - offset and length are untouched; */
			/*
			 * 5 - is_recorded flag in scan structure is set to true. Prevents
			 * multiple recordings of the same scan state.
			 */

			scan.record_header();

			final JPacket packet = scan.scan_packet();
			final int offset = scan.scan_offset();

			scan.scan_offset(offset);

			/*
			 * Now call on any custom bindings. If bindings fail, heuristic scanner
			 * can still match if its enabled. We need to advance the current offset
			 * manually past the header and the gap (between header and payload).
			 * Current header is already recorded and can be peered for binding
			 * invocation.
			 */
			final int next =
			    scanAllBindings(packet, offset + scan.scan_length() + scan.scan_gap());
			scan.scan_next_id(next);

			/*
			 * Native main scan loop implements heuristics. Both post and pre
			 * heuristic checks are supported. Post heuristic checks are done only
			 * after the direct binding checks fail. The above is a "direct binding
			 * check", inkoked through normally registered bindings. For pre, we still
			 * perform direct checks as normal here, the native scan method, overrides
			 * our results. For post, it just checks if we succeeded.
			 */
		}
	}

	/**
	 * @param packet
	 * @param offset
	 */
	private void setAllLengths(final JScan scan, final JPacket packet, int offset) {
		if (this.needJProtocolInitialization) {
			initFromJProtocol(this.protocol);
		}

		final int prefix =
		    (this.lengthMethods[HeaderLength.Type.PREFIX.ordinal()] == null) ? 0
		        : this.lengthMethods[HeaderLength.Type.PREFIX.ordinal()]
		            .getHeaderLength(packet, offset);

		offset += prefix; // Adjust for prefix before the header

		/* Length of header method is mandatory and always present */
		final int header =
		    this.lengthMethods[HeaderLength.Type.HEADER.ordinal()].getHeaderLength(
		        packet, offset);

		final int gap =
		    (this.lengthMethods[HeaderLength.Type.GAP.ordinal()] == null) ? 0
		        : this.lengthMethods[HeaderLength.Type.GAP.ordinal()]
		            .getHeaderLength(packet, offset);

		final int payload =
		    (this.lengthMethods[HeaderLength.Type.PAYLOAD.ordinal()] == null) ? 0
		        : this.lengthMethods[HeaderLength.Type.PAYLOAD.ordinal()]
		            .getHeaderLength(packet, offset);

		final int postfix =
		    (this.lengthMethods[HeaderLength.Type.POSTFIX.ordinal()] == null) ? 0
		        : this.lengthMethods[HeaderLength.Type.POSTFIX.ordinal()]
		            .getHeaderLength(packet, offset);

		// System.out.printf("JHeaderScanner::setAllLengths() - %d:
		// %d,%d,%d,%d,%d\n",
		// this.id, prefix, header, gap, payload, postfix);

		scan.scan_set_lengths(prefix, header, gap, payload, postfix);

	}

	public void setScannerMethod(final AnnotatedScannerMethod method) {
		this.scannerMethod = method;
	}

	@Override
	public String toString() {
		final Formatter out = new Formatter();

		out.format("id=%2d, wasClassLoaded=%s isDirect=%s, bindings=%d method=%s ",
		    this.id, this.lengthMethods != null, isDirect(), this.bindingsList
		        .size(), hasScanMethod());

		return out.toString();
	}

	/**
	 * @return
	 */
	public boolean hasScanMethod() {
		return getScannerMethod() != null;
	}
}
