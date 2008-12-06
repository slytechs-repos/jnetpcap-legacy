/**
 * Copyright (C) 2007 Sly Technologies, Inc. This library is free software; you
 * can redistribute it and/or modify it under the terms of the GNU Lesser
 * General Public License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version. This
 * library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details. You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110_1301 USA
 */
package org.jnetpcap;

/**
 * <p>
 * Constants that represent the Pcap's Data Link Type assignments. The most
 * popular constant is the {@link #EN10MB} (alternatively {@link #CONST_EN10MB})
 * which represents <em>Ethernet2</em> based physical medium. This includes
 * 10, 100, and 1000 mega-bit ethernets.
 * </p>
 * <p>
 * There are 2 tables within PcapDLT enum structure. First is the full table of
 * enum constants, and then there is a duplicate table containing
 * <code>public final static int</code> of contants, prefixed with
 * <code>CONST_</code>. Also the enum constant's field <code>value</code>
 * is public which means that integer DLT constant can also be access using the
 * field directly.
 * </p>
 * Here are 4 examples of how you can use DLT constants in various ways.
 * <h2>Accessing the int DLT value using an enum constant</h2>
 * 
 * <pre>
 * int dlt = pcap.datalink(); // Get DLT value from open Pcap capture
 * if (dlt == PcapDLT.EN10MB.value) {
 * 	// Do something
 * }
 * 
 * // Also can use this more formal approach
 * 
 * if (PcapDLT.EN10MB.equals(dlt)) {
 * 	// Do something
 * }
 * </pre>
 * 
 * <h2>Accessing the int DLT value from integer constants table</h2>
 * 
 * <pre>
 * int dlt = pcap.datalink(); // Get DLT value from open Pcap capture
 * if (dlt == PcapDLT.CONST_EN10MB) {
 * 	// Do something
 * }
 * </pre>
 * 
 * <h2>Converting integer DLT value into a constant</h2>
 * 
 * <pre>
 * int dlt = pcap.datalink(); // Get DLT value from open Pcap capture
 * PcapDLT enumConst = PcapDLT.valueOf(dlt);
 * System.out.println(&quot;The Data Link Type is &quot; + enumConst + &quot; described as &quot;
 *     + enumConst.description);
 * </pre>
 * 
 * <h2>Converting string DLT name into a constant</h2>
 * 
 * <pre>
 * PcapDLT enumConst = PcapDLT.valueOf(&quot;EN10MB&quot;);
 * System.out.println(&quot;The Data Link Type value is &quot; + enumConst.value);
 * </pre>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class PcapDLT {
	public final static PcapDLT NULL;

	public final static PcapDLT EN10MB;

	public final static PcapDLT EN3MB;

	public final static PcapDLT AX25;

	public final static PcapDLT PRONET;

	public final static PcapDLT CHAOS;

	public final static PcapDLT IEEE802;

	public final static PcapDLT ARCNET;

	public final static PcapDLT SLIP;

	public final static PcapDLT PPP;

	public final static PcapDLT FDDI;

	public final static PcapDLT ATM_RFC1483;

	public final static PcapDLT RAW;

	public final static PcapDLT SLIP_BSDOS;

	public final static PcapDLT PPP_BSDOS;

	public final static PcapDLT ATM_CLIP;

	public final static PcapDLT PPP_SERIAL;

	public final static PcapDLT PPP_ETHER;

	public final static PcapDLT SYMANTEC_FIREWALL;

	public final static PcapDLT C_HDLC;

	public final static PcapDLT IEEE802_11;

	public final static PcapDLT FRELAY;

	public final static PcapDLT LOOP;

	public final static PcapDLT ENC;

	public final static PcapDLT LINUX_SLL;

	public final static PcapDLT LTALK;

	public final static PcapDLT ECONET;

	public final static PcapDLT IPFILTER;

	public final static PcapDLT PFLOG;

	public final static PcapDLT CISCO_IOS;

	public final static PcapDLT PRISM_HEADER;

	public final static PcapDLT AIRONET_HEADER;

	public final static PcapDLT PFSYNC;

	public final static PcapDLT IP_OVER_FC;

	public final static PcapDLT SUNATM;

	public final static PcapDLT RIO;

	public final static PcapDLT PCI_EXP;

	public final static PcapDLT AURORA;

	public final static PcapDLT IEEE802_11_RADIO;

	public final static PcapDLT TZSP;

	public final static PcapDLT ARCNET_LINUX;

	public final static PcapDLT JUNIPER_MLPPP;

	public final static PcapDLT JUNIPER_MLFR;

	public final static PcapDLT JUNIPER_ES;

	public final static PcapDLT JUNIPER_GGSN;

	public final static PcapDLT JUNIPER_MFR;

	public final static PcapDLT JUNIPER_ATM2;

	public final static PcapDLT JUNIPER_SERVICES;

	public final static PcapDLT JUNIPER_ATM1;

	public final static PcapDLT APPLE_IP_OVER_IEEE1394;

	public final static PcapDLT MTP2_WITH_PHDR;

	public final static PcapDLT MTP2;

	public final static PcapDLT MTP3;

	public final static PcapDLT SCCP;

	public final static PcapDLT DOCSIS;

	public final static PcapDLT LINUX_IRDA;

	public final static PcapDLT IBM_SP;

	public final static PcapDLT IBM_SN;

	public final static PcapDLT USER0;

	public final static PcapDLT USER1;

	public final static PcapDLT USER2;

	public final static PcapDLT USER3;

	public final static PcapDLT USER4;

	public final static PcapDLT USER5;

	public final static PcapDLT USER6;

	public final static PcapDLT USER7;

	public final static PcapDLT USER8;

	public final static PcapDLT USER9;

	public final static PcapDLT USER10;

	public final static PcapDLT USER11;

	public final static PcapDLT USER12;

	public final static PcapDLT USER13;

	public final static PcapDLT USER14;

	public final static PcapDLT USER15;

	public final static PcapDLT IEEE802_11_RADIO_AVS;

	public final static PcapDLT JUNIPER_MONITOR;

	public final static PcapDLT BACNET_MS_TP;

	public final static PcapDLT PPP_PPPD;

	public final static PcapDLT JUNIPER_PPPOE;

	public final static PcapDLT JUNIPER_PPPOE_ATM;

	public final static PcapDLT GPRS_LLC;

	public final static PcapDLT GPF_T;

	public final static PcapDLT GPF_F;

	public final static PcapDLT GCOM_T1E1;

	public final static PcapDLT GCOM_SERIAL;

	public final static PcapDLT JUNIPER_PIC_PEER;

	public final static PcapDLT ERF_ETH;

	public final static PcapDLT ERF_POS;

	public final static PcapDLT LINUX_LAPD;

	private final static PcapDLT[] values = {
	    NULL = new PcapDLT("NULL", 0),
	    EN10MB = new PcapDLT("EN10MB", 1),
	    EN3MB = new PcapDLT("EN3MB", 2),
	    AX25 = new PcapDLT("AX25", 3),
	    PRONET = new PcapDLT("PRONET", 4),
	    CHAOS = new PcapDLT("CHAOS", 5),
	    IEEE802 = new PcapDLT("IEEE802", 6),
	    ARCNET = new PcapDLT("ARCNET", 7),
	    SLIP = new PcapDLT("SLIP", 8),
	    PPP = new PcapDLT("PPP", 9),
	    FDDI = new PcapDLT("FDDI", 10),
	    ATM_RFC1483 = new PcapDLT("ATM_RFC1483", 11),
	    RAW = new PcapDLT("RAW", 12),
	    SLIP_BSDOS = new PcapDLT("SLIP_BSDOS", 15),
	    PPP_BSDOS = new PcapDLT("PPP_BSDOS", 16),
	    ATM_CLIP = new PcapDLT("ATM_CLIP", 19),
	    PPP_SERIAL = new PcapDLT("PPP_SERIAL", 50),
	    PPP_ETHER = new PcapDLT("PPP_ETHER", 51),
	    SYMANTEC_FIREWALL = new PcapDLT("SYMANTEC_FIREWALL", 99),
	    C_HDLC = new PcapDLT("C_HDLC", 104),
	    IEEE802_11 = new PcapDLT("IEEE802_11", 105),
	    FRELAY = new PcapDLT("FRELAY", 107),
	    LOOP = new PcapDLT("LOOP", 108),
	    ENC = new PcapDLT("ENC", 109),
	    LINUX_SLL = new PcapDLT("LINUX_SLL", 113),
	    LTALK = new PcapDLT("LTALK", 114),
	    ECONET = new PcapDLT("ECONET", 115),
	    IPFILTER = new PcapDLT("IPFILTER", 116),
	    PFLOG = new PcapDLT("PFLOG", 117),
	    CISCO_IOS = new PcapDLT("CISCO_IOS", 118),
	    PRISM_HEADER = new PcapDLT("PRISM_HEADER", 119),
	    AIRONET_HEADER = new PcapDLT("AIRONET_HEADER", 120),
	    PFSYNC = new PcapDLT("PFSYNC", 121),
	    IP_OVER_FC = new PcapDLT("IP_OVER_FC", 122),
	    SUNATM = new PcapDLT("SUNATM", 123),
	    RIO = new PcapDLT("RIO", 124),
	    PCI_EXP = new PcapDLT("PCI_EXP", 125),
	    AURORA = new PcapDLT("AURORA", 126),
	    IEEE802_11_RADIO = new PcapDLT("IEEE802_11_RADIO", 127),
	    TZSP = new PcapDLT("TZSP", 128),
	    ARCNET_LINUX = new PcapDLT("ARCNET_LINUX", 129),
	    JUNIPER_MLPPP = new PcapDLT("JUNIPER_MLPPP", 130),
	    JUNIPER_MLFR = new PcapDLT("JUNIPER_MLFR", 131),
	    JUNIPER_ES = new PcapDLT("JUNIPER_ES", 132),
	    JUNIPER_GGSN = new PcapDLT("JUNIPER_GGSN", 133),
	    JUNIPER_MFR = new PcapDLT("JUNIPER_MFR", 134),
	    JUNIPER_ATM2 = new PcapDLT("JUNIPER_ATM2", 135),
	    JUNIPER_SERVICES = new PcapDLT("JUNIPER_SERVICES", 136),
	    JUNIPER_ATM1 = new PcapDLT("JUNIPER_ATM1", 137),
	    APPLE_IP_OVER_IEEE1394 = new PcapDLT("APPLE_IP_OVER_IEEE1394", 138),
	    MTP2_WITH_PHDR = new PcapDLT("MTP2_WITH_PHDR", 139),
	    MTP2 = new PcapDLT("MTP2", 140),
	    MTP3 = new PcapDLT("MTP3", 141),
	    SCCP = new PcapDLT("SCCP", 142),
	    DOCSIS = new PcapDLT("DOCSIS", 143),
	    LINUX_IRDA = new PcapDLT("LINUX_IRDA", 144),
	    IBM_SP = new PcapDLT("IBM_SP", 145),
	    IBM_SN = new PcapDLT("IBM_SN", 146),
	    USER0 = new PcapDLT("USER0", 147),
	    USER1 = new PcapDLT(" USER1", 148),
	    USER2 = new PcapDLT("USER2", 149),
	    USER3 = new PcapDLT("USER3", 150),
	    USER4 = new PcapDLT("USER4", 151),
	    USER5 = new PcapDLT("USER5", 152),
	    USER6 = new PcapDLT("USER6", 153),
	    USER7 = new PcapDLT("USER7", 154),
	    USER8 = new PcapDLT("USER8", 155),
	    USER9 = new PcapDLT("USER9", 156),
	    USER10 = new PcapDLT("USER10", 157),
	    USER11 = new PcapDLT("USER11", 158),
	    USER12 = new PcapDLT("USER12", 159),
	    USER13 = new PcapDLT("USER13", 160),
	    USER14 = new PcapDLT("USER14", 161),
	    USER15 = new PcapDLT("USER15", 162),
	    IEEE802_11_RADIO_AVS = new PcapDLT("IEEE802_11_RADIO_AVS", 163),
	    JUNIPER_MONITOR = new PcapDLT("JUNIPER_MONITOR", 164),
	    BACNET_MS_TP = new PcapDLT("BACNET_MS_TP", 165),
	    PPP_PPPD = new PcapDLT("PPP_PPPD", 166),
	    JUNIPER_PPPOE = new PcapDLT("JUNIPER_PPPOE", 167),
	    JUNIPER_PPPOE_ATM = new PcapDLT("JUNIPER_PPPOE_ATM", 168),
	    GPRS_LLC = new PcapDLT("GPRS_LLC", 169),
	    GPF_T = new PcapDLT("GPF_T", 170),
	    GPF_F = new PcapDLT("GPF_F", 171),
	    GCOM_T1E1 = new PcapDLT("GCOM_T1E1", 172),
	    GCOM_SERIAL = new PcapDLT("GCOM_SERIAL", 173),
	    JUNIPER_PIC_PEER = new PcapDLT("JUNIPER_PIC_PEER", 174),
	    ERF_ETH = new PcapDLT("ERF_ETH", 175),
	    ERF_POS = new PcapDLT("ERF_POS", 176),
	    LINUX_LAPD = new PcapDLT("LINUX_LAPD", 177), };

	/**
	 * Integer dlt value assigned by libpcap to this constant
	 */
	public final int value;

	/**
	 * Description of the dlt retrieved by quering the native pcap library. The
	 * description is not a static constant part of the API and may change from
	 * native libpcap implementation to implementation.
	 */
	public final String description;

	private final String name;

	private PcapDLT(String name, int value) {
		this.name = name;
		this.value = value;

		// Assign description by quering the native Libpcap library
		String str = Pcap.datalinkValToDescription(value);
		if (str == null) {
			str = name();
		}

		this.description = str;

	}

	/**
	 * Compares the supplied value with the constant's assigned DLT value.
	 * 
	 * @param value
	 *          value to check against this constant
	 * @return true if the supplied value matches the value of the constant,
	 *         otherwise false
	 */
	public boolean equals(int value) {
		return this.value == value;
	}

	public String name() {
		return this.name;
	}

	public static PcapDLT[] values() {
		return values;
	}

	/**
	 * Converts an integer value into a PcapDLT constant.
	 * 
	 * @param value
	 *          Pcap DLT integer value to convert
	 * @return constant assigned to the DLT integer, or null if not found
	 */
	public static PcapDLT valueOf(int value) {
		final PcapDLT[] values = values();
		final int length = values.length;

		for (int i = 0; i < length; i++) {
			if (values[i].value == value) {
				return values[i];
			}

		}

		return null;
	}

	public final static int CONST_NULL = 0;

	public final static int CONST_EN10MB = 1;

	public final static int CONST_EN3MB = 2;

	public final static int CONST_AX25 = 3;

	public final static int CONST_PRONET = 4;

	public final static int CONST_CHAOS = 5;

	public final static int CONST_IEEE802 = 6;

	public final static int CONST_ARCNET = 7;

	public final static int CONST_SLIP = 8;

	public final static int CONST_PPP = 9;

	public final static int CONST_FDDI = 10;

	public final static int CONST_ATM_RFC1483 = 11;

	public final static int CONST_RAW = 12;

	public final static int CONST_SLIP_BSDOS = 15;

	public final static int CONST_PPP_BSDOS = 16;

	public final static int CONST_ATM_CLIP = 19;

	public final static int CONST_PPP_SERIAL = 50;

	public final static int CONST_PPP_ETHER = 51;

	public final static int CONST_SYMANTEC_FIREWALL = 99;

	public final static int CONST_C_HDLC = 104;

	public final static int CONST_IEEE802_11 = 105;

	public final static int CONST_FRELAY = 107;

	public final static int CONST_LOOP = 108;

	public final static int CONST_ENC = 109;

	public final static int CONST_LINUX_SLL = 113;

	public final static int CONST_LTALK = 114;

	public final static int CONST_ECONET = 115;

	public final static int CONST_IPFILTER = 116;

	public final static int CONST_PFLOG = 117;

	public final static int CONST_CISCO_IOS = 118;

	public final static int CONST_PRISM_HEADER = 119;

	public final static int CONST_AIRONET_HEADER = 120;

	public final static int CONST_PFSYNC = 121;

	public final static int CONST_IP_OVER_FC = 122;

	public final static int CONST_SUNATM = 123;

	public final static int CONST_RIO = 124;

	public final static int CONST_PCI_EXP = 125;

	public final static int CONST_AURORA = 126;

	public final static int CONST_IEEE802_11_RADIO = 127;

	public final static int CONST_TZSP = 128;

	public final static int CONST_ARCNET_LINUX = 129;

	public final static int CONST_JUNIPER_MLPPP = 130;

	public final static int CONST_APPLE_IP_OVER_IEEE1394 = 138;

	public final static int CONST_JUNIPER_MLFR = 131;

	public final static int CONST_JUNIPER_ES = 132;

	public final static int CONST_JUNIPER_GGSN = 133;

	public final static int CONST_JUNIPER_MFR = 134;

	public final static int CONST_JUNIPER_ATM2 = 135;

	public final static int CONST_JUNIPER_SERVICES = 136;

	public final static int CONST_JUNIPER_ATM1 = 137;

	public final static int CONST_MTP2_WITH_PHDR = 139;

	public final static int CONST_MTP2 = 140;

	public final static int CONST_MTP3 = 141;

	public final static int CONST_SCCP = 142;

	public final static int CONST_DOCSIS = 143;

	public final static int CONST_LINUX_IRDA = 144;

	public final static int CONST_IBM_SP = 145;

	public final static int CONST_IBM_SN = 146;

	public final static int CONST_USER0 = 147;

	public final static int CONST_USER1 = 148;

	public final static int CONST_USER2 = 149;

	public final static int CONST_USER3 = 150;

	public final static int CONST_USER4 = 151;

	public final static int CONST_USER5 = 152;

	public final static int CONST_USER6 = 153;

	public final static int CONST_USER7 = 154;

	public final static int CONST_USER8 = 155;

	public final static int CONST_USER9 = 156;

	public final static int CONST_USER10 = 157;

	public final static int CONST_USER11 = 158;

	public final static int CONST_USER12 = 159;

	public final static int CONST_USER13 = 160;

	public final static int CONST_USER14 = 161;

	public final static int CONST_USER15 = 162;

	public final static int CONST_IEEE802_11_RADIO_AVS = 163;

	public final static int CONST_JUNIPER_MONITOR = 164;

	public final static int CONST_BACNET_MS_TP = 165;

	public final static int CONST_PPP_PPPD = 166;

	public final static int CONST_JUNIPER_PPPOE = 167;

	public final static int CONST_JUNIPER_PPPOE_ATM = 168;

	public final static int CONST_GPRS_LLC = 169;

	public final static int CONST_GPF_T = 170;

	public final static int CONST_GPF_F = 171;

	public final static int CONST_GCOM_T1E1 = 172;

	public final static int CONST_GCOM_SERIAL = 173;

	public final static int CONST_JUNIPER_PIC_PEER = 174;

	public final static int CONST_ERF_ETH = 175;

	public final static int CONST_ERF_POS = 176;

	public final static int CONST_LINUX_LAPD = 177;

}
