/**
 * 
 */
package org.jnetpcap.protocol;

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.TestUtils;
import org.junit.Test;

/**
 *
 * @author Sly Technologies Inc.
 */
public class TestNullHeader {
	
	private final static String FILE = "Z:\\data/DLT_NULL.rtp.cap";

	@Test
	public void test() {
		
//		System.out.println(JRegistry.toDebugString());
		for (JPacket packet: TestUtils.getIterable(FILE)) {
			System.out.println(packet);
			break;
		}
	}

}
