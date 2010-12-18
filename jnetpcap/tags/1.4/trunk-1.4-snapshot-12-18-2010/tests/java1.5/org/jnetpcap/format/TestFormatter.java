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
package org.jnetpcap.format;

import java.io.IOException;

import junit.framework.TestCase;

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.packet.format.JFormatter;
import org.jnetpcap.packet.format.TextFormatter;
import org.jnetpcap.packet.format.XmlFormatter;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestFormatter
    extends TestCase {
	
//private final static Appendable OUT = TestUtils.DEV_NULL;
	private final static Appendable OUT = System.out;

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {
		super.setUp();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#tearDown()
	 */
	protected void tearDown() throws Exception {
		super.tearDown();
	}

	public void testTextFormatter() throws IOException {
		JFormatter out = new TextFormatter(OUT);
		
		JPacket packet = TestUtils.getPcapPacket("tests/test-vlan.pcap", 0);
		try {
			out.format(packet);
	    
    } catch (Exception e) {
    	e.printStackTrace();
    }
	}

	public void testXmlFormatter() throws IOException {
		JFormatter out = new XmlFormatter(OUT);
		
		JPacket packet = TestUtils.getPcapPacket("tests/test-afs.pcap", 0);

		out.format(packet);
	}
	
	public void testXmlIp4RecordRouteOpt() throws IOException {
		JFormatter out = new XmlFormatter(OUT);
		
		JPacket packet = TestUtils.getPcapPacket("tests/test-icmp-recordroute-opt.pcap", 0);

		out.format(packet);
	}

	
	public void testSubHeader() throws IOException {
		JFormatter out = new TextFormatter(OUT);
		
		JPacket packet = TestUtils.getPcapPacket("tests/test-afs.pcap", 0);

		out.format(packet);
	}

}
