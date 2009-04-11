/**
 * Copyright (C) 2009 Sly Technologies, Inc.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package org.jnetpcap.nio;

import junit.framework.TestCase;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 *
 */
public class TestMappedBuffer
    extends TestCase {
	
	public void testBasic() {
		JBuffer b1 = new JBuffer(10);
		JBuffer b2 = new JBuffer(20);
		JMappedBuffer b = new JMappedBuffer();
		
		int offset = b.add(b1, 0);
		b.add(b2, offset, 18, 2);
		
		b1.setUInt(0, 0x12345678);
		b2.setUInt(0, 0x12345678);
	
		assertEquals(0x12345678, b.getUInt(0));
		assertEquals(0x1234, b.getUInt(10));
	}
	
	public void testBoundary() {
		JBuffer b1 = new JBuffer(10);
		JBuffer b2 = new JBuffer(20);
		JMappedBuffer b = new JMappedBuffer();
		
		int offset = b.add(b1, 0);
		b.add(b2, offset);
		
		b1.setUInt(0, 0x12345678);
		b2.setUInt(0, 0x12345678);
	
		assertEquals(0x12345678, b.getUInt(0));
		assertEquals(0x12345678, b.getUInt(10));
		assertEquals(0x56780000, b.getUInt(8));
	}
}
