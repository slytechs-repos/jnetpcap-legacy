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
package org.jnetpcap.packet;


public interface JBinding extends JDependency {

	public final static int HEADER_NOT_FOUND = 0;
	public static final int NULL_ID = -2;

	/**
	 * Checks the length of the header that has not been bound yet. The returned
	 * length value provides 2 pieces of information. 1st, length of 0 indicates
	 * that the header is not bound. 2nd, length of non zero indicates that the
	 * header is bound and either the entire or trucated length of the header.
	 * 
	 * @param packet
	 *          packet and its data buffer
	 * @param offset
	 *          offset into the packet data buffer where the end of the previous
	 *          header is
	 * @return either full or truncated length of the header or 0 if header is not
	 *         bound at all
	 */
	public abstract int scanForNextHeader(JPacket packet, int offset);

	public abstract int getTargetId();

	public static abstract class DefaultJBinding implements JBinding {

		private final int myId;

		private final int targetId;

		private final int[] dependencyIds;

		/**
		 * Initializes a binding with source ID, target ID and any additional
		 * dendency IDs that need to be specified.
		 * 
		 * @param myId
		 *          ID of the header that owns this binding
		 * @param targetId
		 *          ID of the header to which this binding needs to be applied to.
		 *          The target ID also becomes an automatic dependency since that is
		 *          always the case.
		 * @param dependencyIds
		 *          additional IDs of headers that are referenced in the binding
		 *          expression
		 */
		public DefaultJBinding(int myId, int targetId, int... dependencyIds) {
			this.myId = myId;
			this.targetId = targetId;
			this.dependencyIds = new int[dependencyIds.length + 1];

			System.arraycopy(dependencyIds, 0, this.dependencyIds, 1,
			    dependencyIds.length);

			this.dependencyIds[0] = targetId; // Always the case
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.JBinding#targetId()
		 */
		public int getTargetId() {
			return targetId;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.JDependency#getId()
		 */
		public int getId() {
			return myId;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.JDependency#listDependencies()
		 */
		public int[] listDependencies() {
			return this.dependencyIds;
		}

	}
}