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

import org.jnetpcap.nio.JBuffer;

public abstract class AbstractPeerableAnalysis<A extends JAnalysis, E extends AnalyzerEvent>
    extends AbstractAnalysis<A, E> implements JPeerableAnalysis {

	protected static class AnalysisMemory
	    extends JBuffer {

		/**
		 * @param src
		 */
		public AnalysisMemory() {
			super(Type.POINTER);
		}
	}

	protected final AnalysisMemory memory = new AnalysisMemory();

	/**
	 * @param type
	 */
	public AbstractPeerableAnalysis() {
	}

	@SuppressWarnings("unchecked")
	private <T extends JPeerableAnalysis> int peer(T peer) {

		if (peer.getType() == this.getType()) {
			AbstractPeerableAnalysis<A, E> a =
			    AbstractPeerableAnalysis.class.cast(peer);

			a.synch();
			int r = a.memory.peer(this.memory);
			a.initAfterPeer();

			return r;
		} else {
			return 0;
		}

	}

	/**
	 * Tells the subclass to synchronize java state with native state. Any 
	 */
	protected void synch() {
		// Empty
	}

	/**
	 * Allows a class that is beeing peered to change its internal JAVA state,
	 * cleanup or whatever is neccessary to do as it inherits new native state.
	 */
	protected void initAfterPeer() {
		// Emtpy
	}

	public <T extends JPeerableAnalysis> T getAnalysis(T analysis) {
		return (peer(analysis) == 0) ? null : analysis;
	}

	public <T extends JPeerableAnalysis> boolean hasAnalysis(T analysis) {
		return (getAnalysis(analysis) == null) ? false : true;

	}
}