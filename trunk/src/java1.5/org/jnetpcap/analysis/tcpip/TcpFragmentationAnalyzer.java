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
package org.jnetpcap.analysis.tcpip;

import org.jnetpcap.analysis.FragmentSequence;
import org.jnetpcap.analysis.FragmentSequenceAnalyzer;
import org.jnetpcap.analysis.JAnalyzer;
import org.jnetpcap.analysis.JController;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.header.Tcp;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TcpFragmentationAnalyzer
    extends JController implements FragmentSequenceAnalyzer, JAnalyzer {

	private Tcp tcp = new Tcp();

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.tcpip.FragmentSequenceAnalyzer#timeout(org.jnetpcap.analysis.tcpip.FragmentSequence)
	 */
	public void timeout(FragmentSequence analysis) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Not implemented yet");
	}

	public boolean processPacket(JPacket packet) {

		if (packet.hasHeader(tcp)) {
			return processSegment(packet);
		}
		
		return true;
	}

	/**
	 * @param packet
	 */
	private boolean processSegment(JPacket packet) {
		
		return true;
	}
}
