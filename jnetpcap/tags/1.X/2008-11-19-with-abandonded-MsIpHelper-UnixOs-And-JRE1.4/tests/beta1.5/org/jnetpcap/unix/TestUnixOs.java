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
package org.jnetpcap.unix;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.unix.UnixOs.IfReq;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestUnixOs
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

	/**
	 * 
	 */
	public void testTranslateConstant() {
		if (!UnixOs.isSupported()) {
			return;
		}
		assertEquals(0, UnixOs.translateConstant(UnixOs.PROTOCOL_DEFAULT));

		assertEquals(35111, UnixOs.translateConstant(UnixOs.SIOCGIFHWADDR));

		System.out.println("UnixOs.PF_INET="
		    + UnixOs.translateConstant(UnixOs.PF_INET));
		System.out.println("UnixOs.SOCK_STREAM="
		    + UnixOs.translateConstant(UnixOs.SOCK_STREAM));
		System.out.println("UnixOs.IPPROTO_TCP="
		    + UnixOs.translateConstant(UnixOs.IPPROTO_TCP));
	}

	/**
	 * 
	 */
	public void testSocket() {
		if (!UnixOs.isSupported() || !UnixOs.isSupported(UnixOs.IPPROTO_TCP)) {
			return;
		}

		int d =
		    UnixOs.socket(UnixOs.PF_INET, UnixOs.SOCK_PACKET,
		        UnixOs.PROTOCOL_DEFAULT);
		if (d == -1) {
			fail("socket():" + UnixOs.errno() + " msg="
			    + UnixOs.strerror(UnixOs.errno()));
		}

		UnixOs.close(d);
	}

	/**
	 * 
	 * @throws IOException
	 */
	public void testIoctlGETHWADDR() throws IOException {
		if (!UnixOs.isSupported() || !UnixOs.isSupported(UnixOs.SOCK_PACKET)
		    || !UnixOs.isSupported(UnixOs.SIOCGIFHWADDR)) {
			return;
		}

		int d =
		    UnixOs.socket(UnixOs.PF_INET, UnixOs.SOCK_DGRAM,
		        UnixOs.PROTOCOL_DEFAULT);
		if (d == -1) {
			fail("socket():=" + UnixOs.errno() + " msg="
			    + UnixOs.strerror(UnixOs.errno()));
		}

		final int DEVICE = 2;
		List<PcapIf> ifs = new ArrayList<PcapIf>();
		Pcap.findAllDevs(ifs, System.out);

		// System.out.println("devices=" + ifs);
		System.out.println("device=" + ifs.get(DEVICE).getName());

		IfReq ir = new IfReq();
		ir.ifr_name(ifs.get(DEVICE).getName());

		int r = UnixOs.ioctl(d, UnixOs.SIOCGIFHWADDR, ir);
		if (r == -1) {
			fail("ioctl():=" + UnixOs.errno() + " msg="
			    + UnixOs.strerror(UnixOs.errno()));

		}

		byte[] ha = ir.ifr_hwaddr();
		for (byte b : ha) {
			System.out.printf("%2X:", b);
		}

		System.out.println();

		UnixOs.close(d);

	}

	/**
	 * 
	 * @throws IOException
	 */
	public void testIoctlSIOCGIFMTU() throws IOException {
		if (!UnixOs.isSupported() || !UnixOs.isSupported(UnixOs.SOCK_PACKET)
		    || !UnixOs.isSupported(UnixOs.SIOCGIFMTU)) {
			return;
		}

		int d =
		    UnixOs.socket(UnixOs.PF_INET, UnixOs.SOCK_PACKET,
		        UnixOs.PROTOCOL_DEFAULT);
		if (d == -1) {
			fail("socket():=" + UnixOs.errno() + " msg="
			    + UnixOs.strerror(UnixOs.errno()));
		}

		final int DEVICE = 2;
		List<PcapIf> ifs = new ArrayList<PcapIf>();
		Pcap.findAllDevs(ifs, System.out);

		// System.out.println("devices=" + ifs);
		System.out.println("device=" + ifs.get(DEVICE).getName());

		IfReq ir = new IfReq();
		ir.ifr_name(ifs.get(DEVICE).getName());

		if (UnixOs.ioctl(d, UnixOs.SIOCGIFMTU, ir) < 0) {
			fail("ioctl():=" + UnixOs.errno() + " msg="
			    + UnixOs.strerror(UnixOs.errno()));

		}

		System.out.println("mtu=" + ir.ifr_mtu());

		if (UnixOs.ioctl(d, UnixOs.SIOCGIFFLAGS, ir) < 0) {
			fail("ioctl():=" + UnixOs.errno() + " msg="
			    + UnixOs.strerror(UnixOs.errno()));

		}

		System.out.println("flags=" + ir.ifr_flags());

		UnixOs.close(d);

	}

}
