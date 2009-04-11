/**
 * $Id$
 * Copyright (C) 2006 Sly Technologies, Inc.
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
package com.slytechs.jnetpcap;

import java.io.FileNotFoundException;
import java.io.IOException;

/**
 * <P>This class is the main wrapper around libpcap and winpcap library
 * impelementations. It provides a direct mapping of various library
 * methods from Java.</P>
 * 
 * <P>Usage is very intuitive and only slightly deviates from the strict
 * "C" use since Java is object orientend language.</P>
 * 
 * <PRE style="float: right; border: double; margin-left: 1.5em;">You should read libpcap introduction on
 <A href="http://www.tcpdump.org">tcpdump.org</A> website for general overview 
 and functionality of libpcap.</PRE>
 
 Lets get started with little example on how to inquire about available interfaces, 
 ask the user to pick one of those interfaces for us, open it for capture, 
 compile and install a capture filter  and then
  start processing some packets captured as a result. This is all loosely based on 
  examples you will find on tcpdump.org website but updated for jNetPCAP.
 
 As with libpcap, we first want to find out and get network interface names so we 
 can tell jNetPCAP to open one or more for reading. So first we inquire about the 
 list of interfaces on the system:
 
 <PRE>
 PcapNetworkInterface[] interfaces = Pcap.findAllDevices();
 </PRE>
 
 Now that we have a list of devices, we we print out the list of them and ask the 
 user to pick one to open for capture:
 
 <PRE>
 for(int i = 0; i < interfaces.length; i ++) {
 	System.out.println("#" + i + ": " + interfaces[i].getName());
 }
 
 String l = System.in.readline().trim();
 Integer i = Integer.valueOf(l);
 
 PcapNetworkInterface netInterface = interfaces[i.intValue()];
 </PRE>
 
 
 Next we open up a live capture from the network interface:
 
 <PRE>
 Pcap pcap = Pcap.openLive(netInterface, 64* 1024, true);
 </PRE>
 
 First parameter is the itnerface we want to capture on, second is snaplen 
 and last is if we want the interface in promiscous mode.
 
 Once we have an open interface for capture we can apply a filter to reduce amount 
 of packets captured to something that is interesting to us:
 
 <PRE>
 PcapBpfProgram filter = pcap.compile("port 23", true, netInterface.getNetmask());
 pcap.setFilter(filter);
 </PRE>
 
 And lastly lets do something with the data.
 
 <PRE>
 
 PcapHandler handler = new PcapHandler() {
 
 	public void newPacket(PcapPacket packet, Object userData) {
 		PrintStream out = userData;
 		out.println("Packet captured on: " + packet.getHeader().getTimestamp());
 	}
 };
 
 pcap.loop(<SPAN title="Read 100 packets and exit loop">100</SPAN>, <SPAN title="our hander/callback method above">handler</SPAN>, <SPAN title="Our user object, STDOUT in our case">System.out</SPAN>);
 
 pcap.close();
 </PRE>
 
 This sets up PCAP to capture 100 packets and notify our handler of each packet as each one is captured. 
 Then after 100 packets the loop exits and we call pcap.close() to free up all the resources 
 and we can safely throw away our pcap object. Also you may be curious why we pass System.out 
 as userData to the loop handler. This is simply to demonstrate the typical usage for this kind 
 of parameter. In our case we could easily pass a different PrintStream bound to lets say a network socket 
 and our handler would produce output to it. It doesn't care.
 
 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class Pcap {

	/**
	 * <P>It defines if the adapter has to go in promiscuous mode.</P>
	 * 
	 * <P>It is '1' if you have to open the adapter in promiscuous mode, '0' otherwise.
	 *  Note that even if this parameter is false, the interface could well be in 
	 *  promiscuous mode for some other reason (for example because another capture 
	 *  process with promiscuous mode enabled is currently using that interface). 
	 *  On on Linux systems with 2.2 or later kernels (that have the "any" device), 
	 *  this flag does not work on the "any" device; if an argument of "any" is 
	 *  supplied, the 'promisc' flag is ignored.</P>
	 */
	private static final int PCAP_OPENFLAG_PROMISCOUS = 1;
	
	/**
	 * <P>It defines if the data trasfer (in case of a remote capture) has to be 
	 * done with UDP protocol.</P>
	 * 
	 * <P>If it is '1' if you want a UDP data connection, '0' if you want a TCP 
	 * data connection; control connection is always TCP-based. A UDP connection 
	 * is much lighter, but it does not guarantee that all the captured packets 
	 * arrive to the client workstation. Moreover, it could be harmful in case 
	 * of network congestion. This flag is meaningless if the source is not a 
	 * remote interface. In that case, it is simply ignored. </P>
	 */
	private static final int PCAP_OPENFLAG_DATAX_UDP = 2;
	
	/**
	 * <P>It defines if the remote probe has to capture its own generated traffic.</P>
	 * 
	 * <P>In case the remote probe uses the same interface to capture traffic and 
	 * to send data back to the caller, the captured traffic includes the RPCAP 
	 * traffic as well. If this flag is turned on, the RPCAP traffic is excluded 
	 * from the capture, so that the trace returned back to the collector is does 
	 * not include this traffic.</P> 
	 */
	private static final int PCAP_OPENFLAG_NOCAPTURE_RPCAP = 4;
	
	/**
	 * Pcap object can only be created by calling one of the openX methods. 
	 *
	 */
	private Pcap() {
		/* Empty */
	}
	
	public static Pcap open(String source, int snapLen, int openFlags, int timeout, PcapRemoteAuthentication auth) throws IOException {
		return null;
	}
	
	/**
	 * <P>Open a live capture from the network.</P>
	 * 
	 * <P>pcap_open_live() is used to obtain a packet capture descriptor to look 
	 * at packets on the network. device is a string that specifies the network 
	 * device to open; on Linux systems with 2.2 or later kernels, a device argument 
	 * of "any" or NULL can be used to capture packets from all interfaces. snaplen 
	 * specifies the maximum number of bytes to capture. If this value is less than 
	 * the size of a packet that is captured, only the first snaplen bytes of that 
	 * packet will be captured and provided as packet data. A value of 65535 should
	 * be sufficient, on most if not all networks, to capture all the data 
	 * available from the packet. promisc specifies if the interface is to be put
	 * into promiscuous mode. (Note that even if this parameter is false, the 
	 * interface could well be in promiscuous mode for some other reason.) 
	 * For now, this doesn't work on the "any" device; if an argument of "any"
	 * or NULL is supplied, the promisc flag is ignored. to_ms specifies the read 
	 * timeout in milliseconds. The read timeout is used to arrange that the read 
	 * not necessarily return immediately when a packet is seen, but that it wait 
	 * for some amount of time to allow more packets to arrive and to read multiple 
	 * packets from the OS kernel in one operation. Not all platforms support a 
	 * read timeout; on platforms that don't, the read timeout is ignored. A zero 
	 * value for to_ms, on platforms that support a read timeout, will cause a read 
	 * to wait forever to allow enough packets to arrive, with no timeout. errbuf 
	 * is used to return error or warning text. It will be set to error text when 
	 * pcap_open_live() fails and returns NULL. errbuf may also be set to warning 
	 * text when pcap_open_live() succeds; to detect this case the caller should 
	 * store a zero-length string in errbuf before calling pcap_open_live() and 
	 * display the warning to the user if errbuf is no longer a zero-length string.</P>
	 * 
	 * @param ni 
	 *   Network interface device to open.
	 * @param snapLen 
	 *   Trucate captures to this many bytes if packets are larger.
	 * @param promiscousMode 
	 *   If true interface will be open in promiscous mode, false will be open
	 *   in non-promiscous mode.
	 * @throws IOException  
	 *   Any errors.
	 * @return
	 *   Pcap object that can be used to access the network interface.
	 */
	public static Pcap openLive (PcapNetworkAdapter ni, int snapLen, boolean promiscousMode)  throws IOException{
	
		return null;
	}
	
	public static Pcap openDead(PcapDLT linkType, int snapLen) {
		return null;
	}
	
	public static Pcap openOffline(String fileName) throws IOException {
		return null;
	}

	public static PcapDumper dumpOpen(String filename) throws FileNotFoundException {
		return null;
	}
	
	public boolean setNonBlock(boolean nonBlock) throws IOException {
		return false;
	}
	
	public boolean getNonBlock() throws IOException {
		return false;
	}
	
	public PcapNetworkAdapter[] findAllDevices() throws IOException {
		return null;
	}
	
	public void freeAllDevs(PcapNetworkAdapter[] netInterfaces) {
		/* Empty method, structure automatically released. */
	}
	
	public PcapNetworkAdapter lookupDevice() throws IOException {
		return null;
	}
	
	public PcapIpNetwork lookupNetwork(PcapNetworkAdapter netInterface) throws IOException {
		
		return null;
	}
	
	public int dispatch(int packetCount, PcapHandler listener, Object userData) throws IOException {
		return 0;
	}
	
	public int loop(int packetCount, PcapHandler listener, Object userData) throws IOException {
		return 0;
	}
	
	public PcapPacket next() throws IOException {
		return null;
	}
	
	public PcapPacket nextEx() throws IOException {
		return null;
	}
	
	public void breakLoop() {
		return;
	}
	
	public boolean sendPacket(byte[] data, int length) {
		return false;
	}
	
	public PcapBpfProgram compile(String filter, boolean optimize, byte[] netmask) throws IOException {
		return null;
	}
	
	public PcapBpfProgram compileNoPcap(int snapLen, PcapDLT linkType, String filter, boolean optimize, PcapIpNetwork netmask) throws IOException {
		return null;
	}
	
	public void setFilter(PcapBpfProgram program) throws IOException {
		return;
	}
	
	public void freeCode(PcapBpfProgram program) throws IOException {
		return;
	}
	
	public PcapDLT[] getDataLinkArray(PcapNetworkAdapter adapter) {
		return null;
	}
	
	public PcapDLT getDataLink(PcapNetworkAdapter adapter) {
		return null;
	}
	
	public void setDataLink(PcapDLT dltType) throws IOException {
		return;
	}
	
	public int getSnapshot() {
		return 0;
	}
	
	public boolean isSwapped() {
		return false;
	}
	
	public int getMajorVersion() {
		return 0;
	}
	
	public int getMinorVersion() {
		return 0;
	}
	
	public PcapStatistics stats() throws IOException {
		return null;
	}
	
	public PcapStatistics statsEx() throws IOException {
		return null;
	}
	
	public String getLibVersion() {
		return null;
	}
	
	public void close() throws IOException {
		return;
	}
	
	
}
