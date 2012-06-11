/**
 * 
 */
package org.jnetpcap.protocol;

import junit.framework.TestCase;

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.protocol.lan.NullHeader;
import org.junit.Test;

/**
 *
 * @author Sly Technologies Inc.
 */
public class TestNullHeader {
	
	private final static String FILE = "tests/DLT_NULL.rtp.cap";

	@Test
	public void testNullHeader() {
		
		NullHeader nh = new NullHeader();
		
//		System.out.println(JRegistry.toDebugString());
		for (JPacket packet: TestUtils.getIterable(FILE)) {
//			System.out.println(packet);
//			System.out.println(packet.getState().toDebugString());
//			break;
			
			TestCase.assertTrue("NullHeader by ID missing", packet.hasHeader(JProtocol.NULL_HEADER_ID));
			TestCase.assertTrue("NullHeader by object missing", packet.hasHeader(nh));
		}
	}

}
