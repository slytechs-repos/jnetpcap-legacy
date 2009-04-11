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
package org.jnetpcap.protocol.tcpip;

import org.jnetpcap.packet.analysis.JAnalyzerOptions;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 *
 */
public interface TcpOptions extends JAnalyzerOptions {
	
	public boolean enableSequencer(boolean state);
	
	public boolean enableAssembler(boolean state);
	
	public boolean enableSynAnalysis(boolean state);
	
	public boolean enableFinAnalysis(boolean state);
	
	public boolean enableDispatchErrors(boolean state);
	
	public boolean enableDispatchWarnings(boolean state);
	
	public boolean sequenceAckedSegmentsOnly(boolean state);

}
