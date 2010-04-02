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
package org.jnetpcap.protocol.voip;

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.analysis.AbstractAnalyzer;
import org.jnetpcap.packet.analysis.AnalysisException;
import org.jnetpcap.packet.analysis.AnalyzerListener;
import org.jnetpcap.packet.analysis.FragmentAssembly;
import org.jnetpcap.packet.analysis.FragmentAssemblyEvent;
import org.jnetpcap.packet.analysis.JController;
import org.jnetpcap.packet.analysis.ProtocolSupport;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.HttpHandler;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.TcpAssembler;
import org.jnetpcap.protocol.tcpip.TcpSequencer;
import org.jnetpcap.protocol.voip.Sip.Fields;
import org.jnetpcap.util.JThreadLocal;

/**
 * Http protocol analyzer. Analyzes and maintains state for Http protocol.
 * Requests reassembly of tcp stream.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class SipAnalyzer
    extends
    AbstractAnalyzer implements AnalyzerListener<FragmentAssemblyEvent> {

	private JThreadLocal<Sip> sipLocal = new JThreadLocal<Sip>(Sip.class);

	private JThreadLocal<Tcp> tcpLocal = new JThreadLocal<Tcp>(Tcp.class);

	private TcpSequencer tcpFragAnalyzer =
	    JRegistry.getAnalyzer(TcpSequencer.class);

	private TcpAssembler tcpReassAnalyzer =
	    JRegistry.getAnalyzer(TcpAssembler.class);

	private final ProtocolSupport<SipHandler, Sip> support =
	    new ProtocolSupport<SipHandler, Sip>() {

		    @Override
		    public void dispatch(SipHandler handler, Sip http) {
			    handler.processSip(http);
		    }
	    };

	/**
	 * @param priority
	 */
	public SipAnalyzer() {
		super(200);

		JRegistry.getAnalyzer(JController.class).addAnalyzer(this,
		    JRegistry.lookupId(Sip.class));
		tcpReassAnalyzer.addReassemblyListener(this, null);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.analysis.AbstractAnalyzer#processPacket(org.jnetpcap.packet.JPacket)
	 */
	@Override
	public boolean processPacket(JPacket packet) throws AnalysisException {
		Sip sip = sipLocal.get();

		if (packet.hasHeader(sip)) {
			processSip(packet, sip);
		}

		return true;
	}

	/**
	 * @param packet
	 * @param sip
	 */
	private void processSip(JPacket packet, Sip sip) {
		Tcp tcp = tcpLocal.get();
		final long frame = packet.getFrameNumber();
		if (sip.hasContent()
		    && packet.hasHeader(tcp)
		    && (sip.hasField(Fields.Content_Length) || sip
		        .hasField(Fields.Content_Length))) {

			int tcp_len = tcp.getPayloadLength();
			int content_len = Integer.parseInt(sip.fieldValue(Fields.Content_Length));
			int http_len = content_len + sip.size();

			if (tcp_len >= http_len) {
				Sip userSip = packet.getHeader(new Sip());
				support.fire(userSip);
			} else {

				tcpFragAnalyzer.setFragmentationBoundary(tcp.uniHashCode(), tcp.seq(),
				    http_len);
			}

			// System.out.printf("#%d HttpAnalyzer::hash=%d"
			// + " seq=%d tcp_len=%d http_len=%s frag=%b ", packet.getFrameNumber(),
			// tcp.uniHashCode(), tcp.seq(), http_len, http
			// .fieldValue(Response.Content_Length),
			// (tcp.getPayloadLength() < http_len));
			// System.out.printf("src=%d -> dst->%d\n", tcp.source(),
			// tcp.destination());
			// System.out.printf("http=%s\n", http.toString());

		} else {
			support.fire(packet.getHeader(new Sip()));
		}
	}

	public boolean add(SipHandler o) {

		return this.support.add(o);
	}

	public boolean remove(SipHandler o) {
		return this.support.remove(o);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.analysis.AnalyzerListener#processAnalyzerEvent(org.jnetpcap.packet.analysis.AnalyzerEvent)
	 */
	public void processAnalyzerEvent(FragmentAssemblyEvent evt) {
		if (evt.getType() == FragmentAssemblyEvent.Type.COMPLETE_PDU) {
			FragmentAssembly assembly = evt.getAssembly();
			JPacket packet = assembly.getPacket();
			if (packet.hasHeader(Sip.ID) == false) {
				return;
			}
			
			// System.out.printf("packet=%s\n", packet.getState().toDebugString());
			Sip sip = new Sip();
			if (packet.hasHeader(sip)) {
				support.fire(sip);
			} else {
				System.out.printf("#%d %s\n%s\n", packet.getFrameNumber(), packet,
				    packet.toHexdump());
				System.out.flush();
				throw new IllegalStateException("expected SIP packet (#"
				    + packet.getFrameNumber() + ")");
			}
		}
	}

}
