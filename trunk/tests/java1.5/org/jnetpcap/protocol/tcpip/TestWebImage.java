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
package org.jnetpcap.protocol.tcpip;

import java.awt.Image;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.packet.analysis.JController;
import org.jnetpcap.protocol.application.WebImage;
import org.jnetpcap.protocol.tcpip.Http.ContentType;
import org.jnetpcap.protocol.tcpip.Http.Request;
import org.jnetpcap.protocol.tcpip.Http.Response;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestWebImage
    extends
    TestUtils {

	private static final String HTTP_LARGE = "tests/test-http-large.pcap";

	public static void main(String[] args) {

		new TestWebImage().test1();

	}

	public void test1() {

		/*
		 * This is part of our SWING application. It takes a list of images and
		 * labels and puts them up in 2 different areas of a panel using BoxLayout.
		 * When you click on any item in the list, it changes the image.
		 */
		final ListOfPanels swingDisplay = new ListOfPanels();

		/*
		 * Now display our SWING application with images already in it. Remember
		 * these images were reconstructed from packets within the capture file.
		 */
		swingDisplay.init();

		javax.swing.SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				TestUtils.displayInFrame(swingDisplay);
			}
		});

		/*
		 * Step 1 - add our Http handler to HttpAnalyzer. Get HttpAnalyzer from
		 * registry, it should already be registered.
		 */
		HttpAnalyzer httpAnalyzer = JRegistry.getAnalyzer(HttpAnalyzer.class);
		httpAnalyzer.add(new HttpHandler() {
			private WebImage web = new WebImage();

			/*
			 * Step 2 - our handler routine.
			 */
			public void processHttp(Http http) {
				if (http.getMessageType() != Http.MessageType.RESPONSE) {
					return;
				}

				JPacket packet = http.getPacket(); // Packet this http belongs to
				final long frame = packet.getFrameNumber();
				final String cmd = http.fieldValue(Request.RequestMethod);
				final String code = http.fieldValue(Response.ResponseCode);
				final String ct = http.fieldValue(Response.Content_Type);
				String cl = http.fieldValue(Response.Content_Length);
				final int payload = http.getPayloadLength();

				if ((code != null && code.equals("200") == false)) {
					return; // Skip error messages
				}

				if (ct == null || cl == null) {
					System.out.printf("#%d %s\n", frame, http.header());
					System.out.println("----------------");
					System.out.printf("#%d %s\n", frame, http);
				}

				if (cl == null) {
					cl = Integer.toString(payload);
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
						/*
						 * WebImage header has been integrated as a core protocol.
						 */
						WebImage image = packet.getHeader(web);
						Image img = image.getAWTImage();

						/*
						 * Now add image to our SWING application. Label it with content
						 * type for now.
						 */
						String label = "#" + frame + " " + ct + " " + cl + " bytes";
						swingDisplay.add(img, label);

						break;

					default:
						System.out.printf("#%d code=%s type=%s length=%s/%d\n%s", frame,
						    code, ct, cl, payload, "");
				}
			}

		});

		/*
		 * TestUtils.openLive is a short cut method used by many jUnit tests during
		 * testing, there others such as openOffline.
		 */
		openLive(JRegistry.getAnalyzer(JController.class));
	}
}
