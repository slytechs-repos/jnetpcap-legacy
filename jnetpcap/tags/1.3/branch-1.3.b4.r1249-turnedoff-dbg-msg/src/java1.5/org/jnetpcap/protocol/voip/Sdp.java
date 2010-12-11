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
package org.jnetpcap.protocol.voip;

import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JMappedHeader;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.RegistryHeaderErrors;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.protocol.JProtocol;

// TODO: Auto-generated Javadoc
/**
 * The Class Sdp.
 */
@Header
public class Sdp
    extends
    JMappedHeader {

	/**
	 * The Enum Fields.
	 */
	@Field
	public enum Fields {
		
		/** The Connection info. */
		ConnectionInfo,
		
		/** The Media. */
		Media,
		
		/** The Owner. */
		Owner,
		
		/** The Session name. */
		SessionName,

		/** The Time. */
		Time,

		/** The Version. */
		Version
	}

	/** The ID. */
	public static int ID = JProtocol.SDP_ID;

	static {
		try {
			ID = JRegistry.register(Sdp.class);
		} catch (final RegistryHeaderErrors e) {
			e.printStackTrace();
		}
	}

	/**
	 * Header length.
	 * 
	 * @param buffer
	 *          the buffer
	 * @param offset
	 *          the offset
	 * @return the int
	 */
	@HeaderLength
	public static int headerLength(final JBuffer buffer, final int offset) {
		return buffer.size() - offset;
	}

	/** The attributes. */
	private String[] attributes;

	/** The attributes length. */
	private int attributesLength;

	/** The attributes offset. */
	private int attributesOffset;

	/** The text. */
	private String text;

	/**
	 * Attributes.
	 * 
	 * @return the string[]
	 */
	@Field(offset = 0, length = 10, format = "%s[]")
	public String[] attributes() {
		return this.attributes;
	}

	/**
	 * Attributes length.
	 * 
	 * @return the int
	 */
	@Dynamic(Field.Property.LENGTH)
	public int attributesLength() {
		return this.attributesLength;
	}

	/**
	 * Attributes offset.
	 * 
	 * @return the int
	 */
	@Dynamic(Field.Property.OFFSET)
	public int attributesOffset() {
		return this.attributesOffset;
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.packet.JHeader#decodeHeader()
	 */
	@Override
	protected void decodeHeader() {
		this.text = super.getUTF8String(0, size());

		final String[] lines = this.text.split("\r\n");
		final List<String> list = new ArrayList<String>(10);

		int offset = 0;
		for (String line : lines) {
			final char firstChar = line.charAt(0);
			line = line.substring(2).trim();
			final int length = line.length() * 8;

			// System.out.printf("line='%s'\n", line);

			switch (firstChar) {
				case 'v':
					super.addField(Fields.Version, line, offset, length);
					break;

				case 'o':
					super.addField(Fields.Owner, line, offset, length);
					break;

				case 's':
					super.addField(Fields.SessionName, line, offset, length);
					break;

				case 'c':
					super.addField(Fields.ConnectionInfo, line, offset, length);
					break;

				case 't':
					super.addField(Fields.Time, line, offset, length);
					break;

				case 'm':
					super.addField(Fields.Media, line, offset, length);
					break;

				case 'a':
					list.add(line);
					break;
			}

			offset += (line.length() + 2) * 8;
		}
		this.attributesOffset = offset;
		this.attributesLength = (size() - offset / 8) * 8;
		this.attributes = list.toArray(new String[list.size()]);
	}

	/**
	 * Text.
	 * 
	 * @return the string
	 */
	// @Field(offset = 0, format="#textdump#")
	public String text() {
		return this.text;
	}

	/**
	 * Text length.
	 * 
	 * @return the int
	 */
	// @Dynamic(Field.Property.LENGTH)
	public int textLength() {
		return size() * 8;
	}
}
