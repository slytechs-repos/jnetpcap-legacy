/**
 * Copyright (C) 2008 Sly Technologies, Inc. This library is free software; you
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
package org.jnetpcap.packet.header;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JProtocol;
import org.jnetpcap.packet.annotate.BindingVariable;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.FlowKey;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;

/**
 * Tcp/Ip header definition
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header
@SuppressWarnings("unused")
public class Tcp
    extends JHeader {

	private static final int FLAG_ACK = 0x10;

	private static final int FLAG_CONG = 0x80;

	private static final int FLAG_ECN = 0x40;

	private static final int FLAG_FIN = 0x01;

	private static final int FLAG_PUSH = 0x08;

	private static final int FLAG_RESET = 0x04;

	private static final int FLAG_SYNCH = 0x02;

	private static final int FLAG_URG = 0x20;

	public static final int ID = JProtocol.TCP_ID;

	private static final int FLAG_ECE = 0x40;

	private static final int FLAG_CWR = 0x80;

	@HeaderLength
	public static int headerLength(JBuffer buffer, int offset) {
		final int hlen = (buffer.getUByte(offset + 12) & 0xF0) >> 4;
		return hlen * 4;
	}

	private int hash;

	private Ip4 ip = new Ip4();

	@Field(offset = 8 * 8, length = 16, format = "%x")
	public long ack() {
		return getUInt(8);
	}

	@Field(offset = 16 * 8, length = 16, format = "%x")
	public int checksum() {
		return getUShort(16);
	}

	@Override
	protected void decodeHeader() {
		/*
		 * Generate a bi-directional hashcode
		 */
		if (getPacket() != null && getPacket().hasHeader(ip)) {
			this.hash =
			    (ip.destinationToInt() + destination())
			        ^ (ip.sourceToInt() + source());
		} else {
			this.hash = super.hashCode();
		}
	}

	@BindingVariable
	@Field(offset = 16, length = 16)
	@FlowKey(index = 2, reversable = true)
	public int destination() {
		return getUShort(2);
	}

	@Field(offset = 13 * 8, length = 8, format = "%x")
	public int flags() {
		return getUByte(13);
	}

	/**
   * @return
   */
	@Field(parent = "flags", offset=4, length = 1, format = "%b", display = "ack", description = "acknowledgment")
  public boolean flags_ACK() {
  	return (flags() & FLAG_ACK) != 0;
  }

	@Field(parent = "flags", offset=0, length = 1, format = "%b", display = "fin", description = "closing down connection")
  public boolean flags_FIN() {
  	return (flags() & FLAG_FIN) != 0;
  }

	@Field(parent = "flags", offset=3, length = 1, format = "%b", display = "ack", description = "push current segment of data")
  public boolean flags_PSH() {
  	return (flags() & FLAG_PUSH) != 0;
  }

	@Field(parent = "flags", offset=2, length = 1, format = "%b", display = "ack", description = "reset connection")
  public boolean flags_RST() {
  	return (flags() & FLAG_RESET) != 0;
  }

	@Field(parent = "flags", offset=1, length = 1, format = "%b", display = "ack", description = "synchronize connection, startup")
  public boolean flags_SYN() {
  	return (flags() & FLAG_SYNCH) != 0;
  }

	@Field(parent = "flags", offset=5, length = 1, format = "%b", display = "ack", description = "urgent, out-of-band data")
  public boolean flags_URG() {
  	return (flags() & FLAG_URG) != 0;
  }
	
	@Field(parent = "flags", offset=6, length = 1, format = "%b", display = "ece", description = "ECN echo flag")
  public boolean flags_ECE() {
  	return (flags() & FLAG_ECE) != 0;
  }
	
	@Field(parent = "flags", offset=7, length = 1, format = "%b", display = "cwr", description = "reduced (cwr)")
  public boolean flags_CWR() {
  	return (flags() & FLAG_CWR) != 0;
  }



	@Override
	public int hashCode() {
		return this.hash;
	}

	@Field(offset = 12 * 8, length = 4)
	public int hlen() {
		return (getUByte(12) & 0xF0) >> 4;
	}
	
	@Field(offset = 12 * 8 + 4, length = 4)
	public int reserved() {
		return getUByte(12) & 0x0F;
	}
	
	@Field(offset = 4 * 8, length = 16, format = "%x")
	public long seq() {
		return getUInt(4);
	}

	@BindingVariable
	@Field(offset = 0, length = 16)
	@FlowKey(index = 2, reversable = true)
	public int source() {
		return getUShort(0);
	}
	
	@Field(offset = 18 * 8, length = 16)
	public int urgent() {
		return getUShort(18);
	}

	@Field(offset = 14 * 8, length = 16)
	public int window() {
		return getUShort(14);
	}
}
