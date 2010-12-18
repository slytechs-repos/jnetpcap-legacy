/**
 * Copyright (C) 2010 Sly Technologies, Inc. This library is free software; you
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
package org.jnetsoft.library;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JMemory;

/**
 * Load neccessary native libraries. This helper class loads all the neccessary
 * native libraries in support of the APIs. Since starting with jNetPcap verison
 * 1.4, different levels of native API support are provided, this class loads
 * appropriate API parts and keeps track of what is available/loaded and what is
 * not.
 * <p>
 * The current API is as follows:
 * <p>
 * <b>API100 (Libpcap 1.0.0 API) since jnetpcap version 1.4</b>
 * <ul>
 * <li> {@link Pcap#create Pcap.create}
 * <li> {@link Pcap#activate Pcap.activate}
 * <li> {@link Pcap#setDirection(org.jnetpcap.Pcap.Direction) Pcap.setDirection}
 * <li> {@link Pcap#setSnaplen Pcap.setSnaplen}
 * <li> {@link Pcap#setTimeout Pcap.setTimeout}
 * <li> {@link Pcap#setBufferSize Pcap.setBufferSize}
 * <li> {@link Pcap#canSetRfmon Pcap.canSetRfmon}
 * <li> {@link Pcap#setRfmon Pcap.setRfmon}
 * <li> {@link Pcap#setPromisc(int) Pcap.setPromisc}
 * </ul>
 * </p>
 * <p>
 * <b>API080 (Libpcap 0.8.0 API) since jnetpcap version 1.0</b>
 * <ul>
 * <li> {@link Pcap#breakloop Pcap.breakloop}
 * <li> {@link Pcap#close Pcap.close}
 * <li> {@link Pcap#datalink Pcap.datalink}
 * <li> {@link Pcap#compile(PcapBpfProgram, String, int, int) Pcap.compile}
 * <li> {@link Pcap#dispatch(int, PcapDumper) Pcap.dispatch}
 * <li> {@link Pcap#dumpOpen Pcap.dumpOpen}
 * <li> {@link Pcap#getErr Pcap.getErr}
 * <li> {@link Pcap#getNonBlock Pcap.getNonBlock}
 * <li> {@link Pcap#inject(byte[]) Pcap.inject}
 * <li> {@link Pcap#isSwapped Pcap.isSwapped}
 * <li> {@link Pcap#loop(int, PcapDumper) Pcal.loop}
 * <li> {@link Pcap#majorVersion Pcap.majorVersion}
 * <li> {@link Pcap#minorVersion Pcap.minorVersion}
 * <li> {@link Pcap#next(PcapHeader, org.jnetpcap.nio.JBuffer) Pcap.next}
 * <li> {@link Pcap#nextEx(org.jnetpcap.packet.PcapPacket) Pcap.nextEx}
 * <li> {@link Pcap#sendPacket(byte[]) Pcap.sendPacket}
 * <li> {@link Pcap#setFilter(PcapBpfProgram) Pcap.setFilter}
 * <li> {@link Pcap#setNonBlock Pcap.setNonBlock}
 * <li> {@link Pcap#snapshot Pcap.snapshot}
 * <li> {@link Pcap#stats Pcap.stats}
 * <li> {@link Pcap#compile(PcapBpfProgram, String, int, int) Pcap.compile}
 * <li> {@link Pcap#compileNoPcap Pcap.compileNoPcap}
 * <li> {@link Pcap#datalinkNameToVal Pcap.datalinkNameToVal}
 * <li> {@link Pcap#datalinkValToDescription Pcap.datalinkValToDescription}
 * <li> {@link Pcap#datalinkValToName Pcap.datalinkValToName}
 * <li> {@link Pcap#findAllDevs Pcap.findAllDevs}
 * <li> {@link Pcap#freecode Pcap.freecode}
 * <li> {@link Pcap#libVersion Pcap.libVersion}
 * <li> {@link Pcap#lookupDev Pcap.loopkupDev}
 * <li>
 * {@link Pcap#lookupNet(String, org.jnetpcap.nio.JNumber, org.jnetpcap.nio.JNumber, StringBuilder) Pcap.lookupNet}
 * <li> {@link Pcap#openDead Pcap.openDead}
 * <li> {@link Pcap#openLive Pcap.openLive}
 * <li> {@link Pcap#openOffline Pcap.openOffline}
 * </ul>
 * </p>
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public final class APIDescriptor
    extends
    JMemory {

	/**
	 * Prevent anyone from instantating this class.
	 */
	private APIDescriptor() {
		super(POINTER);
	}

	/**
	 * Register a single specific function, at index, with a java method with
	 * specific name found in the supplied class.
	 * 
	 * @param clazz
	 *          class containing the java method
	 * @param index
	 *          index of the API function
	 * @param name
	 *          name of the java method within clazz
	 * @return 0 on success or negative value on error
	 */
	public native int register(Class<?> clazz, int index, String name);

	/**
	 * Registers all native calls for this API with suplied class.
	 * 
	 * @param clazz
	 *          class for which to register all calls defined for this API
	 * @return array of API call constants that failed to register or an array of
	 *         length 0 if all call registries succeeded
	 */
	public native int registerAll(Class<?> clazz);

	/**
	 * Registers all native calls for this API with suplied class except for the
	 * specific calls supplied.
	 * 
	 * @param clazz
	 *          class for which to register all calls defined for this API
	 * @param exclusions
	 *          an array of indexes of native calls to exclude from registering
	 * @return array of API call constants that failed to register or an array of
	 *         length 0 if all call registries succeeded
	 */
	public native int registerAllExcept(Class<?> clazz, int... exclusions);

}
