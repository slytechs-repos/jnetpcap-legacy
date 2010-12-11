/*
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010 Sly Technologies, Inc.
 *
 * This file is part of jNetPcap.
 *
 * jNetPcap is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as 
 * published by the Free Software Foundation, either version 3 of 
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.jnetpcap.packet;

// TODO: Auto-generated Javadoc
/**
 * The Interface JBinding.
 */
public interface JBinding extends JDependency {

	/**
	 * The Class DefaultJBinding.
	 */
	public static abstract class DefaultJBinding implements JBinding {

		/** The dependency ids. */
		private final int[] dependencyIds;

		/** The my id. */
		private final int myId;

		/** The target id. */
		private final int targetId;

		/**
		 * Instantiates a new default j binding.
		 * 
		 * @param myId
		 *          the my id
		 * @param targetId
		 *          the target id
		 * @param dependencyIds
		 *          the dependency ids
		 */
		public DefaultJBinding(int myId, int targetId, int... dependencyIds) {
			this.myId = myId;
			this.targetId = targetId;
			this.dependencyIds = new int[dependencyIds.length + 1];

			System.arraycopy(dependencyIds, 0, this.dependencyIds, 1,
			    dependencyIds.length);

			this.dependencyIds[0] = targetId; // Always the case
		}

		/**
		 * Gets the id.
		 * 
		 * @return the id
		 */
		public int getId() {
			return myId;
		}

		/* (non-Javadoc)
		 * @see org.jnetpcap.packet.JBinding#getTargetId()
		 */
		public int getTargetId() {
			return targetId;
		}

		/* (non-Javadoc)
		 * @see org.jnetpcap.packet.JBinding#listDependencies()
		 */
		public int[] listDependencies() {
			return this.dependencyIds;
		}

	}

	/** The Constant NULL_ID. */
	public static final int NULL_ID = -2;

	/**
	 * Gets the target id.
	 * 
	 * @return the target id
	 */
	public abstract int getTargetId();

	/**
	 * Checks if is bound.
	 * 
	 * @param packet
	 *          the packet
	 * @param offset
	 *          the offset
	 * @return true, if is bound
	 */
	public abstract boolean isBound(JPacket packet, int offset);
	

	/**
	 * List dependencies.
	 * 
	 * @return the int[]
	 */
	public int[] listDependencies();

	/**
	 * Gets the source id.
	 * 
	 * @return the source id
	 */
	public int getSourceId();
}