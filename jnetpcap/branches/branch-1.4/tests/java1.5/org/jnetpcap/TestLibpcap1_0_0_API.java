/**
 * Copyright (C) 2010 Sly Technologies, Inc. This library is free software; you
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
package org.jnetpcap;

import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.packet.TestUtils;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestLibpcap1_0_0_API
    extends
    TestUtils {

	private final StringBuilder errbuf = new StringBuilder();

	private final List<PcapIf> alldevs = new ArrayList<PcapIf>(10);

	private Pcap pcap = null;

	private int code = Pcap.OK;

	@Override
	protected void setUp() throws Exception {
		errbuf.setLength(0);

		if (alldevs.isEmpty()) {
			if (Pcap.findAllDevs(alldevs, errbuf) != Pcap.OK) {
				fail(errbuf.toString());
			}
		}

	}

	@Override
	protected void tearDown() throws Exception {
		if (pcap != null) {
			pcap.close();
			pcap = null;
		}
	}

	public void testPcapCreate() {

		assertNotNull(errbuf.toString(), pcap =
		    Pcap.create(alldevs.get(0).getName(), errbuf));

	}

	public void testPcapActivate() {

		pcap = Pcap.create(alldevs.get(0).getName(), errbuf);
		assertNotNull(errbuf.toString(), pcap);

		code = pcap.activate();
		assertEquals(pcap.getErr(), Pcap.OK, code);
	}

	public void testPcapSetSnaplenPOSITIVE() {

		pcap = Pcap.create(alldevs.get(0).getName(), errbuf);
		assertNotNull(errbuf.toString(), pcap);

		code = pcap.setSnaplen(128);
		assertEquals(pcap.getErr(), Pcap.OK, code);

		code = pcap.activate();
		assertEquals(pcap.getErr(), Pcap.OK, code);
	}
	
	public void testPcapSetSnaplenNEGATIVE() {
		
		pcap = Pcap.create(alldevs.get(0).getName(), errbuf);
		assertNotNull(errbuf.toString(), pcap);
		
		code = pcap.activate();
		assertEquals(pcap.getErr(), Pcap.OK, code);
		
		code = pcap.setSnaplen(128);
		assertTrue(pcap.getErr(), code != Pcap.OK);
	}
	
	public void testPcapSetBufferSizePOSITIVE() {
		
		pcap = Pcap.create(alldevs.get(0).getName(), errbuf);
		assertNotNull(errbuf.toString(), pcap);
		
		code = pcap.setBufferSize(128000);
		assertEquals(pcap.getErr(), Pcap.OK, code);
		
		code = pcap.activate();
		assertEquals(pcap.getErr(), Pcap.OK, code);
	}
	
	public void testPcapSetBufferSizeNEGATIVE() {
		
		pcap = Pcap.create(alldevs.get(0).getName(), errbuf);
		assertNotNull(errbuf.toString(), pcap);
		
		code = pcap.activate();
		assertEquals(pcap.getErr(), Pcap.OK, code);
		
		code = pcap.setSnaplen(128000);
		assertTrue(pcap.getErr(), code != Pcap.OK);
	}
	
	public void testPcapSetTimeoutPOSITIVE() {
		
		pcap = Pcap.create(alldevs.get(0).getName(), errbuf);
		assertNotNull(errbuf.toString(), pcap);
		
		code = pcap.setTimeout(128000);
		assertEquals(pcap.getErr(), Pcap.OK, code);
		
		code = pcap.activate();
		assertEquals(pcap.getErr(), Pcap.OK, code);
	}
	
	public void testPcapSetTimeoutNEGATIVE() {
		
		pcap = Pcap.create(alldevs.get(0).getName(), errbuf);
		assertNotNull(errbuf.toString(), pcap);
		
		code = pcap.activate();
		assertEquals(pcap.getErr(), Pcap.OK, code);
		
		code = pcap.setTimeout(128000);
		assertTrue(pcap.getErr(), code != Pcap.OK);
	}
	
	public void testPcapSetPromiscTruePOSITIVE() {
		
		pcap = Pcap.create(alldevs.get(0).getName(), errbuf);
		assertNotNull(errbuf.toString(), pcap);
		
		code = pcap.setPromisc(1);
		assertEquals(pcap.getErr(), Pcap.OK, code);
		
		code = pcap.activate();
		assertEquals(pcap.getErr(), Pcap.OK, code);
	}
	
	public void testPcapSetPromiscTrueNEGATIVE() {
		
		pcap = Pcap.create(alldevs.get(0).getName(), errbuf);
		assertNotNull(errbuf.toString(), pcap);
		
		code = pcap.activate();
		assertEquals(pcap.getErr(), Pcap.OK, code);
		
		code = pcap.setPromisc(1);
		assertTrue(pcap.getErr(), code != Pcap.OK);
	}
	
	public void testPcapSetPromiscFalsePOSITIVE() {
		
		pcap = Pcap.create(alldevs.get(0).getName(), errbuf);
		assertNotNull(errbuf.toString(), pcap);
		
		code = pcap.setPromisc(0);
		assertEquals(pcap.getErr(), Pcap.OK, code);
		
		code = pcap.activate();
		assertEquals(pcap.getErr(), Pcap.OK, code);
	}
	
	public void testPcapSetPromiscFalseNEGATIVE() {
		
		pcap = Pcap.create(alldevs.get(0).getName(), errbuf);
		assertNotNull(errbuf.toString(), pcap);
		
		code = pcap.activate();
		assertEquals(pcap.getErr(), Pcap.OK, code);
		
		code = pcap.setPromisc(0);
		assertTrue(pcap.getErr(), code != Pcap.OK);
	}

}
