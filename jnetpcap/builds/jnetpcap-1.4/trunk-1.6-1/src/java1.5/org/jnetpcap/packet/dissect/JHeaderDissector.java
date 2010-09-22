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
package org.jnetpcap.packet.dissect;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JSubHeader;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 * @param
 *         <P>
 */
public interface JHeaderDissector<P extends JHeader> {

	/**
	 * Retrieves the short sub-header mapping. The header-map is 64-bits long and
	 * contains a set bit for every protocol ID that is present within the
	 * underlying collection. The sub-header ID is the index into the map. If the
	 * underlying collection map is longer then 64-bits then the underlying
	 * implementation provides a different map accessor, in addition to this one,
	 * that returns the full map
	 * 
	 * @return 64-bit sub-header mappings
	 */
	public long getSubHeaderMap();

	/**
	 * @return
	 */
	public int getCount();

	/**
	 * @param id
	 * @return
	 */
	public int getInstanceCount(int id);

	/**
	 * @param <H>
	 * @param id
	 * @return
	 */
	public <H extends JSubHeader<P>> H getSubHeader(int id);

	/**
	 * @param <H>
	 * @param id
	 * @return
	 */
	public <H extends JSubHeader<P>> H getSubHeader(int id, int instance);

	/**
	 * @param index
	 * @return
	 */
	public JSubHeader<P> getSubHeaderByIndex(int index);

	/**
	 * @param <H>
	 * @param header
	 * @return
	 */
	public <H extends JSubHeader<P>> boolean hasSubHeader(H header);

	/**
	 * @param <H>
	 * @param header
	 * @param instance
	 * @return
	 */
	public <H extends JSubHeader<P>> boolean hasSubHeader(H header, int instance);

	/**
	 * @param id
	 * @return
	 */
	public boolean hasSubHeader(int id);

}
