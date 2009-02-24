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
package org.jnetpcap.newstuff;

import java.io.IOException;

import org.jnetpcap.analysis.JController;
import org.jnetpcap.analysis.tcpip.http.HttpAnalyzer;
import org.jnetpcap.analysis.tcpip.http.HttpHandler;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.RegistryHeaderErrors;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.packet.format.JFormatter;
import org.jnetpcap.packet.format.TextFormatter;
import org.jnetpcap.packet.header.Html;
import org.jnetpcap.packet.header.Http;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestHttp2
    extends TestUtils {

	static {
		try {
			JRegistry.register(Http.class);
			JRegistry.register(Html.class);
		} catch (RegistryHeaderErrors e) {
			e.printStackTrace();
		}
	}

	private final JFormatter out = new TextFormatter(System.out);

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

	public void test1() throws IOException {
		JPacket packet = getPcapPacket(HTTP, 5);

		JFormatter out = new TextFormatter(System.out);

		out.format(packet);
	}

	public void test2() throws IOException {

		HttpAnalyzer httpAnalyzer = JRegistry.getAnalyzer(HttpAnalyzer.class);
		httpAnalyzer.add(new HttpHandler() {

			public void processHttp(Http http) {
				try {
					if (http.getMessageType() == null) {
						return;
					}
					out.printf("\n\n#%d *** %s ***", http.getPacket().getFrameNumber(),
					    http.getMessageType());
					out.format(http);

				} catch (IOException e) {
					e.printStackTrace();
				}
			}

		});

		// JPacket packet = getPcapPacket(HTTP, 51);
		// controller.nextPacket(packet, null);

		super.openOffline(HTTP, JRegistry.getAnalyzer(JController.class));

	}

}
