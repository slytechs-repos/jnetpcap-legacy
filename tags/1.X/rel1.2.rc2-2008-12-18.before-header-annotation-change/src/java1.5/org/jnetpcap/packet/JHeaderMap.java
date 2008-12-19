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

import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.packet.format.JField;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class JHeaderMap<B extends JHeader>
    extends JHeader implements JCompoundHeader<B> {

	public final static int MAX_HEADERS = 16;

	protected long optionsBitmap = -1;

	protected int[] optionsOffsets = new int[MAX_HEADERS];
	
	protected int[] optionsLength = new int[MAX_HEADERS];

	protected final JHeader[] X_HEADERS = new JHeader[MAX_HEADERS];
	
	public JHeaderMap() {
	  super();
	  
	  inspect();
	}

	/**
	 * @param id
	 * @param fields
	 * @param name
	 * @param nicname
	 * @param unordered
	 */
	public JHeaderMap(int id, JField[] fields, String name, String nicname,
	    JHeader[] unordered) {
		super(id, fields, name, nicname);

		reorderAndSave(unordered);
	}

	/**
	 * @param id
	 * @param name
	 */
	public JHeaderMap(int id, String name, JHeader[] unordered) {
		super(id, name);
		reorderAndSave(unordered);
	}

	/**
	 * @param id
	 * @param name
	 * @param nicname
	 */
	public JHeaderMap(int id, String name, String nicname, JHeader[] unordered) {
		super(id, name, nicname);
		reorderAndSave(unordered);
	}

	@Override
	public void setSubHeaders(JHeader[] headers) {
		reorderAndSave(headers);
	}
	
	public <T extends JSubHeader<B>> T getSubHeader(T header) {

		final int offset = optionsOffsets[header.getId()];
		final int length = optionsLength[header.getId()];
		header.peer(this, offset, length);
		header.setOffset(offset);
		header.setLength(length);
		header.setParent(this);

		return header;
	}
	
	@SuppressWarnings("unchecked")
  private  JHeader getSubHeader(JHeader header) {
		
		JSubHeader<B> sub = (JSubHeader<B>)header;

		final int id = sub.getId();
		final int offset = optionsOffsets[id];
		final int length = optionsLength[id];
		sub.peer(this, offset, length);
		sub.setOffset(offset);
		sub.setLength(length);
		sub.setParent(this);

		return header;
	}


	public JHeader[] getSubHeaders() {
		List<JHeader> headers = new ArrayList<JHeader>();
		for (int i = 0; i < MAX_HEADERS; i++) {
			if (hasSubHeader(i) && X_HEADERS[i] != null) {
				JHeader header = X_HEADERS[i];
				getSubHeader(header);
				headers.add(X_HEADERS[i]);
			}
		}
		return headers.toArray(new JHeader[headers.size()]);
	}

	public boolean hasSubHeader(int id) {
		return (optionsBitmap & (1 << id)) > 0;
	}

	public <T extends JSubHeader<B>> boolean hasSubHeader(T header) {
		if (hasSubHeader(header.getId())) {
			getSubHeader(header);

			return true;
		} else {
			return false;
		}
	}

	private void reorderAndSave(JHeader[] unordered) {

		for (JHeader u : unordered) {
			X_HEADERS[u.getId()] = u;
		}
	}
	
	public boolean hasSubHeaders() {
		return this.optionsBitmap != 0;
	}

}
