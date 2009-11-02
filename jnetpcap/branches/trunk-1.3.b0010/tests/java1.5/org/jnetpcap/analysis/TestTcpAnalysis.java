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

import java.io.IOException;
import java.io.InputStream;

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.packet.analysis.EventDumper;
import org.jnetpcap.packet.analysis.FragmentAssembly;
import org.jnetpcap.packet.analysis.JController;
import org.jnetpcap.packet.format.JFormatter;
import org.jnetpcap.packet.format.TextFormatter;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.application.WebImage;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.TcpAnalyzer;
import org.jnetpcap.protocol.tcpip.TcpAssembler;
import org.jnetpcap.protocol.tcpip.TcpSequencer;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestTcpAnalysis
    extends TestUtils {

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

	@SuppressWarnings("unchecked")
	public void testMySQLUsingTcpAnalyzer() {

		EventDumper dumper = new EventDumper();

		JController controller = JRegistry.getAnalyzer(JController.class);
		TcpAnalyzer tcpAnalyzer = new TcpAnalyzer();
		controller.addAnalyzer(tcpAnalyzer, JProtocol.TCP_ID);
		tcpAnalyzer.addTcpStreamListener(dumper, null);

		openOffline(MYSQL, controller);

	}

	/**
	 * Analyze a HTTP/JPEG capture file that has
	 * <ol>
	 * <li> TCP segments out of sequence
	 * <li> 1 TCP segment is IP fragmented, where 1st fragment is not captured as
	 * its delivered via a different network part, but both parts arrive
	 * eventually
	 * <li> The incomplete segment is non-identifiable as TCP segment since the
	 * 1st fragment is missing that contains the TCP header.
	 * <li> The missing segment was filled in only because of an ACK from the
	 * receiver that it actually has received the reassembled IP dgram, our TCP
	 * segment.
	 * </ol>
	 * 
	 * <pre>
	 *   ACKs | Frame #s      | Seq #/Length
	 *  ------------------------------------
	 *        +-----+
	 *    16  |15,17|              1/0
	 *        +-----+--+
	 *    20  |     | ?|           1/1460
	 *        +     +--+--+
	 *        |        |21|     1461/1219
	 *        +  +--+  +--+
	 *  22,23 |  |19|     |     2681/5
	 *        +  +--+     +--+
	 *        |           |74|  2686/1
	 *        +--+--+--+--+--+
	 *        [time ==&gt;] 
	 * </pre>
	 */
	@SuppressWarnings("unchecked")
	public void test2UsingTcpAnalyzer() {

		EventDumper dumper = new EventDumper();

		JController controller = JRegistry.getAnalyzer(JController.class);
		TcpAnalyzer tcpAnalyzer = new TcpAnalyzer();
		controller.addAnalyzer(tcpAnalyzer, JProtocol.TCP_ID);
		tcpAnalyzer.addTcpStreamListener(dumper, null);

		openOffline(HTTP, controller, "tcp port 3200");

	}

	@SuppressWarnings("unchecked")
	public void testTcpSequence() {

		EventDumper dumper = new EventDumper();

		JController controller = JRegistry.getAnalyzer(JController.class);
		TcpAnalyzer tcpAnalyzer = new TcpAnalyzer();
		final TcpSequencer frag = new TcpSequencer();
		controller.addAnalyzer(tcpAnalyzer, JProtocol.TCP_ID);
		// tcpAnalyzer.addTcpStreamListener(dumper, null);
		frag.addFragmentationListener(dumper);
		frag.setFragmentationBoundary(0xa010de5, 937638703L, 191777L);

		openOffline(HTTP, controller);
	}

	@SuppressWarnings("unchecked")
	public void testTcpReassembly() {

		EventDumper dumper = new EventDumper();

		JController controller = JRegistry.getAnalyzer(JController.class);
		TcpAnalyzer tcpAnalyzer = new TcpAnalyzer();
		final TcpSequencer frag = new TcpSequencer();
		final TcpAssembler reassembler = new TcpAssembler(frag);
		controller.addAnalyzer(tcpAnalyzer, JProtocol.TCP_ID);
		// tcpAnalyzer.addTcpStreamListener(dumper, null);
		frag.setFragmentationBoundary(0xa010de5, 937638703L, 191777L);

		controller.add(new JPacketHandler<Object>() {
			JFormatter out = new TextFormatter(System.out);

			Tcp tcp = new Tcp();

			public void nextPacket(JPacket packet, Object user) {
				try {
					if (packet.hasHeader(tcp)
					    && tcp.hasAnalysis(FragmentAssembly.class)) {
					}

					out.format(packet);
					System.out.flush();

				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}

		}, null);

		reassembler.addReassemblyListener(dumper, null);
		openOffline(HTTP, controller);

		System.out.println("--------FINISHED------------");
	}

	@SuppressWarnings("unchecked")
	public void testJpegMockup() {

		/*
		 * Dump all events to stdout
		 */
		EventDumper dumper = new EventDumper();

		/*
		 * Main analyzer controller
		 */
		JController controller = JRegistry.getAnalyzer(JController.class);

		/*
		 * Main TCP analyzer. Tracks ACKs, retransmissions, builds TcpDuplexStream
		 * and TcpStream objects, etc..
		 */
		TcpAnalyzer tcpAnalyzer = new TcpAnalyzer();

		/*
		 * Tracks contigues TCP segments via sequence numbers
		 */
		final TcpSequencer frag = new TcpSequencer();

		/*
		 * Reassembles multiple TCP segments into large packets, InputStream,
		 * SlidingWindows
		 */
		final TcpAssembler reassembler = new TcpAssembler(frag);
		controller.addAnalyzer(tcpAnalyzer, JProtocol.TCP_ID);
		// tcpAnalyzer.addTcpStreamListener(dumper, null);

		/*
		 * This will normally be calculated by HttpAnalyzer, but because it doesn't
		 * exist yet, we manually tell frag-analyzer to track down these sequences
		 * for us. TcpAssembler is listening to its events and will reassemble
		 * into a single large Http only based packet.
		 */
		frag.setFragmentationBoundary(0xa010de5, 937638703L, 191777L);

		/*
		 * Tell frag-analyzer not to dispatch packets to the user that are part of
		 * reassembly. They are still accesible through the analysis data attached
		 * to the packets that are returned. Note that consume will consume all
		 * related packets, not just the fragments, so if there is a related Icmp
		 * messages that says something about the TCP segment, that ICMP message
		 * will also be consumed. The packets that are consumed are still there but
		 * now they are attached as analysis to the TCP header.
		 */
		frag.setConsume(true);

		controller.add(new JPacketHandler<Object>() {
			JFormatter out = new TextFormatter(System.out);

			Tcp tcp = new Tcp();

			Http http = new Http();

			WebImage img = new WebImage();

			public void nextPacket(JPacket packet, Object user) {
				try {
					if (packet.hasHeader(img)) {

						/*
						 * Content can be reassembled completely into memory, depending how
						 * much memory we want to dedicate for this purpose. Remember the
						 * content could be very very large. The call to getContent()
						 * signals TcpAssembler to reassembly all related TCP segments
						 * into a single buffer.
						 */
						if (img.length() < 1024 * 1024) {
//							JBuffer buf = img.getReassembledBuffer();
//							JPacket asPacket = img.getReassembledPacket();

						} else {

							/*
							 * Or for larger content, read one byte at a time using IO stream.
							 * getInputStream signals TcpAssembler that we are going to be
							 * reading 1 byte at a time out of each TCP segment. This only
							 * requires the use of TcpSequencer to tell us what is
							 * the next ACKed TCP segment in the chain.
							 */
							InputStream in = img.getInputStream();
							/*
							 * Or for larger content, read a buffer full at a time while
							 * sliding left edge of buffer/window. getSlidingBuffer() signals
							 * TcpAssembler that we will be reassembling various portions of
							 * this part of the stream. We will be adding new segments on the
							 * right, while letting already processed segments on the left
							 * expire and be released. Both sequence analysis and reassembly
							 * will be required.
							 */
//							SlidingBuffer window = img.getSlidingBuffer();
						}

					}

					if (packet.hasHeader(http) && http.isResponse() && http.hasContent()) {
						out.format(packet);
					}

					if (packet.hasHeader(img)) {

					}
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}

		}, null);

		reassembler.addReassemblyListener(dumper, null);
		openOffline(HTTP, controller);
	}

}
