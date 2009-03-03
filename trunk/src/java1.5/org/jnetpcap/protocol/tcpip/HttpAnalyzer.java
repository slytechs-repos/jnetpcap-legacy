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
package org.jnetpcap.protocol.tcpip;

import org.jnetpcap.analysis.AbstractAnalyzer;
import org.jnetpcap.analysis.AnalyzerListener;
import org.jnetpcap.analysis.FragmentAssemblyEvent;
import org.jnetpcap.analysis.FragmentAssembly;
import org.jnetpcap.analysis.JController;
import org.jnetpcap.analysis.ProtocolSupport;
import org.jnetpcap.analysis.tcpip.AnalysisException;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.header.Tcp;
import org.jnetpcap.protocol.tcpip.Http.Response;
import org.jnetpcap.util.JThreadLocal;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class HttpAnalyzer
    extends AbstractAnalyzer implements AnalyzerListener<FragmentAssemblyEvent> {

	private JThreadLocal<Http> httpLocal = new JThreadLocal<Http>(Http.class);

	private JThreadLocal<Tcp> tcpLocal = new JThreadLocal<Tcp>(Tcp.class);

	private TcpSequencer tcpFragAnalyzer =
	    JRegistry.getAnalyzer(TcpSequencer.class);

	private TcpAssembler tcpReassAnalyzer =
	    JRegistry.getAnalyzer(TcpAssembler.class);

	private final ProtocolSupport<HttpHandler, Http> support =
	    new ProtocolSupport<HttpHandler, Http>() {

		    @Override
		    public void dispatch(HttpHandler handler, Http http) {
			    handler.processHttp(http);
		    }
	    };

	/**
	 * @param priority
	 */
	public HttpAnalyzer() {
		super(200);

		JRegistry.getAnalyzer(JController.class).addAnalyzer(this,
		    JRegistry.lookupId(Http.class));
		tcpReassAnalyzer.addReassemblyListener(this, null);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.AbstractAnalyzer#processPacket(org.jnetpcap.packet.JPacket)
	 */
	@Override
	public boolean processPacket(JPacket packet) throws AnalysisException {
		Http http = httpLocal.get();

		if (packet.hasHeader(http)) {
			processHttp(packet, http);
		}

		return true;
	}

	/**
	 * @param packet
	 * @param http
	 */
	private void processHttp(JPacket packet, Http http) {
		Tcp tcp = tcpLocal.get();
		if (http.hasContent() && packet.hasHeader(tcp)
		    && http.hasField(Response.Content_Length)) {

			int tcp_len = tcp.getPayloadLength();
			int content_len =
			    Integer.parseInt(http.fieldValue(Response.Content_Length));
			int http_len = content_len + http.size();

			if (tcp_len >= http_len) {
				Http userHttp = packet.getHeader(new Http());
				support.fire(userHttp);
			} else {

				tcpFragAnalyzer.setFragmentationBoundary(tcp.uniHashCode(), tcp.seq(),
				    http_len);
			}

//			System.out.printf(
//			    "#%d HttpAnalyzer::hash=%d seq=%d tcp_len=%d http_len=%s frag=%b ",
//			    packet.getFrameNumber(), tcp.uniHashCode(), tcp.seq(), http_len, http
//			        .fieldValue(Response.Content_Length),
//			    (tcp.getPayloadLength() < http_len));
//			System.out.printf("src=%d -> dst->%d\n", tcp.source(), tcp.destination());
//			System.out.printf("http=%s\n", http.toString());

		} else {
			// support.fire(packet.getHeader(new Http()));
		}
	}

	public boolean add(HttpHandler o) {
		return this.support.add(o);
	}

	public boolean remove(HttpHandler o) {
		return this.support.remove(o);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.AnalyzerListener#processAnalyzerEvent(org.jnetpcap.analysis.AnalyzerEvent)
	 */
	public void processAnalyzerEvent(FragmentAssemblyEvent evt) {
		if (evt.getType() == FragmentAssemblyEvent.Type.COMPLETE_PDU) {
			FragmentAssembly assembly = evt.getAssembly();
			JPacket packet = assembly.getPacket();
//			System.out.printf("packet=%s\n", packet.getState().toDebugString());
			Http http = new Http();
			if (packet.hasHeader(http)) {
				support.fire(http);
			} else {
				throw new IllegalStateException("expected HTTP packet");
			}
		}
	}

}
