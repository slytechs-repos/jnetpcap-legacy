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
package org.jnetpcap.ms;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JNumber;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestMSIpHelper
    extends TestCase {

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

	public void testGetIpInfo() {
		if (!MSIpHelper.isSupported()) {
			return;
		}

		int r;
		JNumber size = new JNumber();
		if ((r = MSIpHelper.getInterfaceInfo(null, size)) != MSIpHelper.ERROR_INSUFFICIENT_BUFFER) {
			fail("" + r);
		}

		MSIpInterfaceInfo info = new MSIpInterfaceInfo(size.intValue());
		if ((r = MSIpHelper.getInterfaceInfo(info, size)) != MSIpHelper.NO_ERROR) {
			fail("" + r + ", size=" + size.intValue());
		}

		for (int i = 0; i < info.numAdapters(); i++) {
			MSIpAdapterIndexMap adapter = info.adapter(i);
			assertNotNull(adapter);
			System.out.printf("#%d: adapter.name=%s\n", i, adapter.name());

			MSMibIfRow row = new MSMibIfRow();
			row.dwIndex(adapter.index());
			if ((r = MSIpHelper.getIfEntry(row)) != MSIpHelper.NO_ERROR) {
				fail("" + r);
			}

			System.out.printf("\tstatus=%d\n", row.dwAdminStatus());
			System.out.printf("\tMAC=%s\n", asString(row.bPhysAddr()));
			System.out.printf("\tspeed=%d\n", row.dwSpeed());
		}

	}

	public void testMapIpInfoWithPcapFindAllDevs() throws IOException {
		if (!MSIpHelper.isSupported()) {
			return;
		}
		
		List<PcapIf> alldevs = new ArrayList<PcapIf>();
		Pcap.findAllDevs(alldevs, System.out);
		for (PcapIf i: alldevs) {
			System.out.println(i.getName());
		}

		int r = MSIpHelper.NO_ERROR;
		JNumber size = new JNumber();
		if ((r = MSIpHelper.getInterfaceInfo(null, size)) != MSIpHelper.ERROR_INSUFFICIENT_BUFFER) {
			fail("" + r);
		}

		MSIpInterfaceInfo info = new MSIpInterfaceInfo(size.intValue());
		if ((r = MSIpHelper.getInterfaceInfo(info, size)) != MSIpHelper.NO_ERROR) {
			fail("" + r + ", size=" + size.intValue());
		}

		for (int i = 0; i < info.numAdapters(); i++) {
			MSIpAdapterIndexMap adapter = info.adapter(i);
			assertNotNull(adapter);
			System.out.printf("#%d: adapter.name=%s\n", i, adapter.name());

			MSMibIfRow row = new MSMibIfRow();
			row.dwIndex(adapter.index());
			if ((r = MSIpHelper.getIfEntry(row)) != MSIpHelper.NO_ERROR) {
				fail("" + r);
			}

			System.out.printf("\tstatus=%d\n", row.dwAdminStatus());
			System.out.printf("\tMAC=%s\n", asString(row.bPhysAddr()));
			System.out.printf("\tspeed=%d\n", row.dwSpeed());
		}

	}

	/**
	 * @param bs
	 * @return
	 */
	private String asString(byte[] bs) {
		StringBuilder buf = new StringBuilder();
		for (byte b : bs) {
			if (buf.length() != 0) {
				buf.append(':');
			}
			buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
		}

		return buf.toString();
	}
//\DEVICE\TCPIP_
}
