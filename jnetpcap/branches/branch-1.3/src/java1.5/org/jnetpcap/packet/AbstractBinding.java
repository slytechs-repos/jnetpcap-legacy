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

import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.packet.structure.AnnotatedHeaderLengthMethod;
import org.jnetpcap.packet.structure.HeaderDefinitionError;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class AbstractBinding<H extends JHeader> implements JBinding {

	private final int targetId;

	private final int sourceId;

	private final H header;

	private AnnotatedHeaderLengthMethod[] lengthMethods;

	public AbstractBinding(
	    Class<? extends JHeader> sourceClass,
	    Class<H> targetClass) {

		this.sourceId = JRegistry.lookupId(sourceClass);
		this.targetId = JRegistry.lookupId(targetClass);

		try {
			this.header = targetClass.newInstance();
		} catch (InstantiationException e) {
			throw new IllegalStateException(e);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		}

		try {
			this.lengthMethods =
			    AnnotatedHeaderLengthMethod.inspectClass(targetClass);
		} catch (HeaderDefinitionError e) {
			this.lengthMethods = null;
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JBinding#getSourceId()
	 */
	public int getSourceId() {
		return this.sourceId;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JBinding#getTargetId()
	 */
	public int getTargetId() {

		return this.targetId;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JBinding#isBound(org.jnetpcap.packet.JPacket, int)
	 */
	public boolean isBound(JPacket packet, int offset) {

		if (this.lengthMethods != null) {
			final int prefix =
			    lengthMethods[HeaderLength.Type.PREFIX.ordinal()].getHeaderLength(
			        packet, offset);
			
			packet.peer(header, offset + prefix, lengthMethods[HeaderLength.Type.HEADER
			    .ordinal()].getHeaderLength(packet, offset));
		} else {
			packet.peer(header, offset, packet.remaining(offset));
		}
		return isBound(packet, header);
	}

	public abstract boolean isBound(JPacket packet, H header);

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JBinding#listDependencies()
	 */
	public int[] listDependencies() {
		return new int[] { targetId };
	}

}
