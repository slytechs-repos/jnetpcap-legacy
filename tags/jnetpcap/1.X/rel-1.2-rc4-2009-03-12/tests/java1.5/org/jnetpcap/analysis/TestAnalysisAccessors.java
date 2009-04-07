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
package org.jnetpcap.analysis;

import java.util.Iterator;

import junit.framework.TestCase;

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.packet.analysis.JAnalysis;
import org.jnetpcap.protocol.lan.Ethernet;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestAnalysisAccessors
    extends TestCase {

	private static final String AFS = "tests/test-afs.pcap";
	
	private static final JAnalysis ANALYSIS = new JAnalysis() {

		public <T extends JAnalysis> T getAnalysis(T analysis) {
	    throw new UnsupportedOperationException("Not implemented yet");
    }

		public int getType() {
	    throw new UnsupportedOperationException("Not implemented yet");
    }

		public <T extends JAnalysis> boolean hasAnalysis(T analysis) {
	    throw new UnsupportedOperationException("Not implemented yet");
    }

		public <T extends JAnalysis> boolean hasAnalysis(Class<T> analysis) {
	    throw new UnsupportedOperationException("Not implemented yet");
    }

		public boolean hasAnalysis(int type) {
	    throw new UnsupportedOperationException("Not implemented yet");
    }

		public int peer(JAnalysis peer) {
	    throw new UnsupportedOperationException("Not implemented yet");
    }

		public String getTitle() {
	    // TODO Auto-generated method stub
	    throw new UnsupportedOperationException("Not implemented yet");
    }

		public String getShortTitle() {
	    // TODO Auto-generated method stub
	    throw new UnsupportedOperationException("Not implemented yet");
    }

		public String[] getText() {
	    // TODO Auto-generated method stub
	    throw new UnsupportedOperationException("Not implemented yet");
    }

		public Iterator<JAnalysis> iterator() {
	    // TODO Auto-generated method stub
	    throw new UnsupportedOperationException("Not implemented yet");
    }

	};

	private JPacket packet;

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {
		packet = TestUtils.getPcapPacket(AFS, 5);
	}

	public void testPacketNullAnalysis() {
		assertNull(packet.getState().getAnalysis());
	}

	public void testPacketSetHeader1Item() {
		packet.getState().setAnalysis(ANALYSIS);
		packet.getState().setAnalysis(ANALYSIS);
		packet.getState().setAnalysis(ANALYSIS);
		
		Ethernet eth = new Ethernet();
		packet.getHeader(eth);
		eth.getState().setAnalysis(packet.getState(), ANALYSIS);

//		Ip4 ip = new Ip4();
//		packet.getHeader(ip);
//		ip.getState().setAnalysis(packet.getState(), ANALYSIS);

//		System.out.printf("testPacketSetHeader1Item(): \n%s\n %s", packet.getState()
//		    .toDebugString(), ANALYSIS.toString());

		assertNotNull(packet.getState().getAnalysis());
	}

}
