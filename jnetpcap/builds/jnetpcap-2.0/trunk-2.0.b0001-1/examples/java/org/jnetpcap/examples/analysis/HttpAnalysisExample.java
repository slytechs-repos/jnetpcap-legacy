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
package org.jnetpcap.examples.analysis;

import java.awt.Image;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.RegistryHeaderErrors;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.packet.analysis.JController;
import org.jnetpcap.packet.analysis.JControllerOptions;
import org.jnetpcap.protocol.application.WebImage;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.HttpAnalyzer;
import org.jnetpcap.protocol.tcpip.HttpHandler;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Http.ContentType;
import org.jnetpcap.protocol.tcpip.Http.Request;
import org.jnetpcap.protocol.tcpip.Http.Response;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class HttpAnalysisExample {

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		/*
		 * JController implements JControllerOptions but we downcast to
		 * JControllerOptions since we are only interested in changing its options.
		 * By downcasting we narrow down what the IDEs will suggest, to only option
		 * accessor methods.
		 */
		JControllerOptions controller = JRegistry.getAnalyzer(JController.class);

		/**
		 * No packets will be dispatched to JPacketHandler, since there isn't one
		 * anyway. All packets that have been analyzed will be consumed.
		 */
		// controller.consumePackets(true);

		/**
		 * Step 1 - add our Http handler to HttpAnalyzer. Get HttpAnalyzer from
		 * registry, it should already be registered.
		 */
		HttpAnalyzer httpAnalyzer = JRegistry.getAnalyzer(HttpAnalyzer.class);
		HttpHandler handler = new HttpHandler() {

			/*
			 * Step 2 - our handler routine.
			 */
			public void processHttp(Http http) {

				JPacket packet = http.getPacket(); // Packet this http belongs to
				final long frame = packet.getFrameNumber();

				System.out.printf("\n#%-3d: %8s", frame, http.getMessageType());

				if (http.getMessageType() == null) {
					System.out.printf(" http=%s\ntcp=%s\nip=%s", http, packet
					    .getHeader(new Tcp()), packet.getHeader(new Ip4()));
				}

				if (http.getMessageType() == Http.MessageType.REQUEST) {
					System.out.printf(" url:%s", http.fieldValue(Request.RequestUrl));
				}

				// if (http.getPayloadLength() > 0) {
				// System.out.printf("\n#%-3d: http=%s", frame, http);
				// }

				/*
				 * Http is normal http header that has been decoded.
				 */
				if (http.getMessageType() != Http.MessageType.RESPONSE) {
					return;
				}

				/*
				 * Responses always have a content type, since we are looking for
				 * specific content that has been predefined, we can use enum constants.
				 * We're not interested in anything else, otherwise we'd have to use
				 * http.contentType() method which returns a string.
				 */
				ContentType type = http.contentTypeEnum();

				switch (type) {
					case GIF:
					case PNG:
					case JPEG:
						System.out.printf(" Content-Type:%s Content-Length:%s", http
						    .fieldValue(Response.Content_Type), http
						    .fieldValue(Response.Content_Length));

						/*
						 * WebImage header is already defined under tests source tree, but
						 * we can't really use it for our example yet.
						 */
						WebImage image = packet.getHeader(new WebImage());
						Image img = image.getAWTImage();

						break;

					default:
						if (http.contentType() == null) {
							System.out.printf(" Found content type %s", http.contentType());
						} else {
							System.out.printf(" method %s", http
							    .fieldValue(Response.ResponseCode));

						}
				}
			}

		};

		httpAnalyzer.add(handler);

		/*
		 * Step 3 - normal open capture file stuff
		 */
		StringBuilder errbuf = new StringBuilder();
		Pcap pcap = Pcap.openOffline(TestUtils.HTTP, errbuf);
		if (pcap == null) {
			System.err.println(errbuf.toString());
			System.exit(1);
		}

		/*
		 * Step 4 - We enter our loop. The main thing to consider is that we are
		 * passing JController as the primary handler for libpcap packets. Notice
		 * JController is registered with JRegistry. It knows how to pass packets on
		 * to other analyzers, especially the HttpAnalyzer in our case. We could add
		 * a JPacketHandler as a listener to JController, which would pass on
		 * regular packets back to us, after they have been analyzed. This is the
		 * same, as if we registered our handler directly with the loop. All packets
		 * will be passed back to us. There are however few differenced. The main
		 * difference is that packet returned from JController as opposed to
		 * directly from the Pcap.loop or dispatch methods, is that JController may
		 * have buffered them, while analyzers where working through the stream of
		 * packets. Once the appropriate release signals were sent by any analyzer
		 * that had a hold on JController's outbound queue, all the packets are
		 * fetched to JPacketHandler listeners as the outboud queue is drained. In
		 * our example we chose to work with HttpAnalyzer directly and its
		 * HttpHandler, which is more specific to http protocol.
		 */
		pcap.loop(Pcap.LOOP_INFINATE, JRegistry.getAnalyzer(JController.class),
		    null);

		// pcap.loop(Pcap.LOOP_INFINATE, new JPacketHandler<Object>() {
		// private Http http = new Http();
		//
		// public void nextPacket(JPacket packet, Object user) {
		// if (packet.hasHeader(http)
		// && http.getMessageType() == Http.MessageType.RESPONSE) {
		// System.out.printf("#%d http=%s\n", packet.getFrameNumber(), http
		// , http.toHexdump());
		// }
		// }
		//
		// }, null);

		/*
		 * Always close the pcap handle after we are done
		 */
		pcap.close();
		System.exit(0);
	}
}
