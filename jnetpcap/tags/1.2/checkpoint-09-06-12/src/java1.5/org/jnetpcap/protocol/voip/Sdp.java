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
package org.jnetpcap.protocol.voip;

import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JMappedHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.RegistryHeaderErrors;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header
public class Sdp
    extends
    JMappedHeader {
	
	public static int ID;

	static {
		try {
	    ID = JRegistry.register(Sdp.class);
    } catch (RegistryHeaderErrors e) {
	    e.printStackTrace();
    }
	}

	
	private String text;
	private String[] attributes;
	private int attributesOffset;
	private int attributesLength;

	@HeaderLength
	public static int headerLength(JBuffer buffer, int offset) {
		return buffer.size() - offset;
	}
	
	@Bind(to=Sip.class)
	public static boolean bindToSip(JPacket packet, Sip sip) {
//		System.out.printf("bind: contentType=%s\n", sip.contentType());
		return sip.contentType().startsWith("application/sdp");
	}

	@Override
	protected void decodeHeader() {
		text = super.getUTF8String(0, size());
		
		final String[] lines = text.split("\r\n");
		final List<String> list = new ArrayList<String>(10);
		
		int offset = 0;
		for (String line: lines) {
			char firstChar = line.charAt(0);
			line = line.substring(2).trim();
			int length = line.length() * 8;
			
//			System.out.printf("line='%s'\n", line);
			
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
	
	@Dynamic(Field.Property.OFFSET)
	public int attributesOffset() {
		return this.attributesOffset;
	}
	
	@Dynamic(Field.Property.LENGTH)
	public int attributesLength() {
		return this.attributesLength;
	}
	
	@Field(offset = 0, length = 10, format="%s[]")
	public String[] attributes() {
		return this.attributes;
	}
	
	@Field
	public enum Fields {
		Version,
		Owner,
		SessionName,
		ConnectionInfo,
		Time,
		Media
	}
	
//	@Dynamic(Field.Property.LENGTH)
	public int textLength() {
		return size() * 8;
	}
	
//	@Field(offset = 0, format="#textdump#")
	public String text() {
		return this.text;
	}
}
