/*
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010 Sly Technologies, Inc.
 *
 * This file is part of jNetPcap.
 *
 * jNetPcap is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as 
 * published by the Free Software Foundation, either version 3 of 
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.jnetpcap.protocol.tcpip;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JHeaderChecksum;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.FlowKey;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.util.checksum.Checksum;

// TODO: Auto-generated Javadoc
/**
 * The Class Udp.
 */
@Header(length = 8)
public class Udp
    extends
    JHeader implements JHeaderChecksum {

	/** The Constant ID. */
	public static final int ID = JProtocol.UDP_ID;

	/* (non-Javadoc)
	 * @see org.jnetpcap.packet.JHeaderChecksum#calculateChecksum()
	 */
	public int calculateChecksum() {

		if (getIndex() == -1) {
			throw new IllegalStateException("Oops index not set");
		}

		final int ipOffset = getPreviousHeaderOffset();

		return Checksum.inChecksumShouldBe(checksum(), Checksum.pseudoUdp(
		    this.packet, ipOffset, getOffset()));
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.packet.JHeaderChecksum#checksum()
	 */
	@Field(offset = 6 * 8, length = 16, format = "%x")
	public int checksum() {
		return getUShort(6);
	}

	/**
	 * Checksum.
	 * 
	 * @param value
	 *          the value
	 */
	public void checksum(final int value) {
		super.setUShort(6, value);
	}

	/**
	 * Checksum description.
	 * 
	 * @return the string
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String checksumDescription() {

		if (isFragmented()) {
			return "supressed for fragments";
		}

		if (isPayloadTruncated()) {
			return "supressed for truncated packets";
		}

		final int checksum = checksum();
		if (checksum == 0) {
			return "omitted";
		}

		final int crc16 = calculateChecksum();
		if (checksum == crc16) {
			return "correct";
		} else {
			return "incorrect: 0x" + Integer.toHexString(crc16).toUpperCase();
		}
	}

	/**
	 * Destination.
	 * 
	 * @return the int
	 */
	@Field(offset = 2 * 8, length = 16)
	@FlowKey(index = 2, reversable = true)
	public int destination() {
		return getUShort(2);
	}

	/**
	 * Destination.
	 * 
	 * @param value
	 *          the value
	 */
	public void destination(final int value) {
		setUShort(2, value);
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.packet.JHeaderChecksum#isChecksumValid()
	 */
	public boolean isChecksumValid() {

		if (isFragmented()) {
			return true;
		}

		if (getIndex() == -1) {
			throw new IllegalStateException("Oops index not set");
		}

		final int ipOffset = getPreviousHeaderOffset();

		return Checksum.pseudoUdp(this.packet, ipOffset, getOffset()) == 0;
	}

	/**
	 * Length.
	 * 
	 * @return the int
	 */
	@Field(offset = 4 * 8, length = 16)
	public int length() {
		return getUShort(4);
	}

	/**
	 * Length.
	 * 
	 * @param value
	 *          the value
	 */
	public void length(final int value) {
		setUShort(4, value);
	}

	/**
	 * Source.
	 * 
	 * @return the int
	 */
	@Field(offset = 0, length = 16)
	@FlowKey(index = 2, reversable = true)
	public int source() {
		return getUShort(0);
	}

	/**
	 * Source.
	 * 
	 * @param value
	 *          the value
	 */
	public void source(final int value) {
		setUShort(0, value);
	}

}
