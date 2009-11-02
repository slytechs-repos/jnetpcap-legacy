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
package org.jnetpcap.bugs;

import java.nio.ByteBuffer;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.PeeringException;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.protocol.JProtocol;

/**
 * 2828030 JMemoryPacket doesn't set wirelen.
 * <p>
 * Several JMemoryPacket constructors do not set the required "wirelen" header
 * property. This causes exceptions to be thrown by the quick-scanner.
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class Bug2828030_wirelen_not_set_in_JMemoryPacket
    extends
    TestUtils {

	private byte[] data;

	/* (non-Javadoc)
   * @see junit.framework.TestCase#setUp()
   */
  @Override
  protected void setUp() throws Exception {
		PcapPacket packet = getPcapPacket(L2TP, 0);

		data = packet.getByteArray(0, packet.size());
  }

	/* (non-Javadoc)
   * @see junit.framework.TestCase#tearDown()
   */
  @Override
  protected void tearDown() throws Exception {
  	data = null;
  }

	/**
	 * 
	 */
	public void testScannerExceptionWithByteArray() {
		
		JMemoryPacket mem = new JMemoryPacket(data);

		assertNotNull(mem);

		mem.scan(JProtocol.ETHERNET_ID);
	}

	/**
	 * 
	 */
	public void testScannerExceptionWithIByteArray() {
		
		JMemoryPacket mem = new JMemoryPacket(JProtocol.ETHERNET_ID, data);

		assertNotNull(mem);
	}

	/**
	 * 
	 */
	public void testScannerExceptionWithJBuffer() {
		
		JBuffer buf = new JBuffer(data);
		JMemoryPacket mem = new JMemoryPacket(buf);

		assertNotNull(mem);

		mem.scan(JProtocol.ETHERNET_ID);
	}

	/**
	 * 
	 */
	public void testScannerExceptionWithIJBuffer() {
		
		JBuffer buf = new JBuffer(data);
		JMemoryPacket mem = new JMemoryPacket(JProtocol.ETHERNET_ID, buf);

		assertNotNull(mem);
	}

	/**
	 * @throws PeeringException
	 */
	public void testScannerExceptionWithByteBuffer() throws PeeringException {
		
		ByteBuffer buf = ByteBuffer.allocateDirect(data.length);
		buf.put(data).clear();

		JMemoryPacket mem = new JMemoryPacket(buf);

		assertNotNull(mem);
		
		mem.scan(JProtocol.ETHERNET_ID);
	}

	/**
	 * @throws PeeringException
	 */
	public void testScannerExceptionWithIByteBuffer() throws PeeringException {
		
		ByteBuffer buf = ByteBuffer.allocateDirect(data.length);
		buf.put(data).clear();

		JMemoryPacket mem = new JMemoryPacket(JProtocol.ETHERNET_ID, buf);

		assertNotNull(mem);

	}

}
