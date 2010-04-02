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
package org.jnetpcap.packet.analysis;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public interface JControllerOptions extends JAnalyzerOptions {

	/**
	 * No packets will be dispatched to any listening packet handlers after the
	 * packet has been analyzed. This does not affect other analyzers that my
	 * dispatch to a protocol or analyzer specific handler.
	 * 
	 * @param state
	 *          true prevents JController from dispatching packets to its
	 *          listeners
	 * @return old value
	 */
	public boolean consumePackets(boolean state);

	/**
	 * A way to disable any protocol and packet analysis and allow packets to just
	 * pass through and be dispatched to registered packet handlers.
	 * 
	 * @param state
	 *          true enables analysis, false disables it
	 * @return old value
	 */
	public boolean enableAnalysis(boolean state);

	/**
	 * A way to disable only the packet analysis. Packet analysis differs from
	 * protocol analysis. Packet analysis is not protocol specific and analyzes
	 * the entire packet (i.e. packet statistics).
	 * 
	 * @param state
	 *          true enables analysis, false disables it
	 * @return old value
	 */
	public boolean enablePacketAnalysis(boolean state);

	/**
	 * A way to enable/disable only the protocol analysis. Packet analysis is
	 * still done on entire packets, but per protocol analysis is can either
	 * enabled or disabled.
	 * 
	 * @param state
	 *          true enables analysis, false disables it
	 * @return old value
	 */
	public boolean enableProtocolAnalysis(boolean state);

}
