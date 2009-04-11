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
package org.jnetpcap.newstuff.analysis;

import junit.framework.TestCase;

import org.jnetpcap.analysis.AnalyzerListener;
import org.jnetpcap.analysis.tcpip.FieldAnalysis;
import org.jnetpcap.analysis.tcpip.FragmentSequence;
import org.jnetpcap.analysis.tcpip.FragmentSequenceEvent;
import org.jnetpcap.analysis.tcpip.HeaderAnalysis;
import org.jnetpcap.analysis.tcpip.Ip4Analyzer;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.packet.header.Ethernet;
import org.jnetpcap.packet.header.Ip4;
import org.jnetpcap.packet.header.Tcp;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestAnalysisSyntax
    extends TestCase {

	private final static String HTTP = "tests/test-http-jpeg.pcap";

	public void testAnalysisSyntax() {
		JPacket packet = TestUtils.getPcapPacket(HTTP, 5);

		/* Header objects */
		Ethernet ether = new Ethernet();
		Ip4 ip = new Ip4();
		Tcp tcp = new Tcp();

		/* Analysis objects */
		Ip4Analyzer ipAnalyzer = new Ip4Analyzer();

		FragmentSequence ipSequence = new FragmentSequence();
		FragmentSequence tcpSequence = new FragmentSequence();
		HeaderAnalysis etherValidation;

//		ipAnalyzer
//		    .addFragmentationListener(new AnalyzerListener<FragmentSequenceEvent>() {
//
//			    public void processAnalyzerEvent(FragmentSequenceEvent evt) {
//				    // TODO Auto-generated method stub
//				    throw new UnsupportedOperationException("Not implemented yet");
//			    }
//
//		    });

		/*
		 * If this packet is a fragment of a larger datagram or stream, we will have
		 * packet sequence of all the other fragments in ipSequence.
		 */
		if (packet.hasHeader(ip) && ip.hasAnalysis(ipSequence)) {
		}

		if (packet.hasHeader(tcp) && tcp.hasAnalysis(tcpSequence)) {
		}

		/*
		 * If headers were validated, we may have errors. We get a per header field
		 * analysis object which we can use to report errors and protocol state.
		 */
		if (packet.hasHeader(ether) && ether.hasAnalysis(HeaderAnalysis.class)) {

			etherValidation = ether.getAnalysis(HeaderAnalysis.class);

			if (etherValidation.hasFieldErrors()) {

				for (FieldAnalysis f : etherValidation.getFieldErrors()) {
					System.out.printf("field %s has errors: %s", f.getFieldName(), f
					    .getErrorMessage());
				}

			}
		}
	}
}
