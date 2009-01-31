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

import org.jnetpcap.analysis.tcpip.TcpAnalyzer;
import org.jnetpcap.packet.JProtocol;
import org.jnetpcap.packet.TestUtils;

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

		JController controller = new JController();
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
	public void test2UsingTcpAnalyzer() {

		EventDumper dumper = new EventDumper();

		JController controller = new JController();
		TcpAnalyzer tcpAnalyzer = new TcpAnalyzer();
		controller.addAnalyzer(tcpAnalyzer, JProtocol.TCP_ID);
		tcpAnalyzer.addTcpStreamListener(dumper, null);

		openOffline(HTTP, controller);

	}

}
