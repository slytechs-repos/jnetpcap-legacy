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

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.RegistryHeaderErrors;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.packet.analysis.FragmentSequence;
import org.jnetpcap.packet.analysis.JController;
import org.jnetpcap.packet.format.JFormatter;
import org.jnetpcap.packet.format.TextFormatter;
import org.jnetpcap.protocol.application.WebImage;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.HttpAnalyzer;
import org.jnetpcap.protocol.tcpip.HttpHandler;
import org.jnetpcap.protocol.tcpip.Http.ContentType;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestHttp2
    extends
    TestUtils {

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

	public void test2() throws IOException, RegistryHeaderErrors {
		final FragmentSequence seq = new FragmentSequence();
		JRegistry.register(WebImage.class);

		HttpAnalyzer httpAnalyzer = JRegistry.getAnalyzer(HttpAnalyzer.class);
		httpAnalyzer.add(new HttpHandler() {

			public void processHttp(Http http) {
				if (http.getMessageType() != Http.MessageType.RESPONSE) {
					out.printf("\n\n#%d *** %s *** ", http.getPacket()
					    .getFrameNumber(), http.getMessageType());
					return;
				}
				out.printf("\n\n#%d *** %s len=%s *** ", http.getPacket()
				    .getFrameNumber(), http.getMessageType(), String.valueOf(http
				    .fieldValue(Http.Response.Content_Length)), http.toString());

				ContentType type = http.contentTypeEnum();
				if (type != ContentType.JPEG) {
					return;
				}

				switch (type) {
					case JPEG:
						WebImage jpeg = http.getPacket().getHeader(new WebImage());
						System.out.printf("\nJPEG reassembled lenth=%d\n", jpeg.size());
						// printSequence(http.getPacket().getAnalysis(Tcp.ID, seq));
						break;

					default:
						System.out.printf("Unknown content type %s\n", type);
				}
			}

		});

		// JPacket packet = getPcapPacket(HTTP, 51);
		// controller.nextPacket(packet, null);

		openOffline(HTTP, JRegistry.getAnalyzer(JController.class));

	}

	private void printSequence(FragmentSequence seq) {
		System.out.printf("seq=%s\n", seq.toString());
	}
}
