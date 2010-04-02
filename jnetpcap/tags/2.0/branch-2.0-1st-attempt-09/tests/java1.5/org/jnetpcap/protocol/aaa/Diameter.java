package org.jnetpcap.protocol.aaa;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeaderMap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.RegistryHeaderErrors;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.protocol.tcpip.Tcp;

@Header
public class Diameter
    extends JHeaderMap<Diameter> {
	
	public static int ID;

	static {
		try {
			ID = JRegistry.register(Diameter.class);
		} catch (final RegistryHeaderErrors e) {
			e.printStackTrace();
		}
	}
	
	@Bind(to=Tcp.class)
	public static boolean bindToTcp(JPacket packet, Tcp tcp) {
		return tcp.destination() == 3868 || tcp.source() == 3868;
	}
	
	@HeaderLength
	public static int headerLength(JBuffer buffer, int offset) {
	    return (int) buffer.getUInt(offset) & 0x00FFFFFF;	
	}
	
	// Diameter header accessors
	@Field(offset = 0, length = 8, format = "%x")
	public int getVersion() {
		return super.getUByte(0);
	}
	
	@Field(offset = 8, length = 24, format = "%x")
	public int getMessageLength() {
		return (int) super.getUInt(0) & 0x00FFFFFF;
	}
	
	@Field(offset = 0, length = 8, format = "%x")
	public int getCommandFlags() {
		return super.getUByte(4);
	}
	
	@Field(offset = 0, length = 24, format = "%x")
	public int getCommandCode() {
		return (int) super.getUInt(4) & 0x00FFFFFF;
	}
}