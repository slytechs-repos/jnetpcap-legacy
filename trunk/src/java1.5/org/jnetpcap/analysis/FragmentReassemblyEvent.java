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
package org.jnetpcap.analysis;

import org.jnetpcap.analysis.AnalyzerEvent.AnalyzerEventType;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class FragmentReassemblyEvent
    extends AbstractAnalyzerEvent<FragmentReassemblyEvent.Type> {

	private final FragmentReassembly assembly;

	public enum Type implements AnalyzerEventType {
		COMPLETE_PDU,
		INCOMPLETE_PDU,
	}

	/**
	 * @param source
	 * @param type
	 */
	public FragmentReassemblyEvent(FragmentAssembler source, Type type,
	    FragmentReassembly assembly) {
		super(source, type);
		this.assembly = assembly;
	}

	public static FragmentReassemblyEvent createCompletePdu(
	    FragmentAssembler source,
	    FragmentReassembly assembly) {

		return new FragmentReassemblyEvent(source, Type.COMPLETE_PDU, assembly);
	}

	public static FragmentReassemblyEvent createIncompletePdu(
	    FragmentAssembler source,
	    FragmentReassembly assembly) {

		return new FragmentReassemblyEvent(source, Type.INCOMPLETE_PDU, assembly);
	}

	public final FragmentReassembly getAssembly() {
		return this.assembly;
	}

}
