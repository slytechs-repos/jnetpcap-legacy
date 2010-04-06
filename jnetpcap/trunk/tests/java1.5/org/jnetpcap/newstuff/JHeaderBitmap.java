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
package org.jnetpcap.newstuff;

import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JSubHeader;
import org.jnetpcap.packet.structure.AnnotatedHeader;

/**
 * @param <B>
 *          header baseclass that all sub-header's should be enclosed in
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("unused")
public class JHeaderBitmap<B extends JHeader> implements JHeaderContainer<B> {

	public final static int MAX_HEADERS = 64;

	protected long optionsBitmap = -1;

	protected int[] optionsOffsets = new int[MAX_HEADERS];

	protected int[] optionsLength = new int[MAX_HEADERS];

	protected final JHeader[] X_HEADERS = new JHeader[MAX_HEADERS];

	private final JHeader parent;

	private int count;

	public JHeaderBitmap(JHeader parent) {
		super();
		this.parent = parent;

		/*
		 * Create sub-header instances using default constructor from annotation
		 */
		reorderAndSave(createHeaderInstances(parent.getAnnotatedHeader()
		    .getHeaders()));
	}

	private static JHeader[] createHeaderInstances(AnnotatedHeader... headers) {
		JHeader[] h = new JHeader[headers.length];

		for (int i = 0; i < h.length; i++) {
			h[i] = createHeaderInstance(headers[i]);
		}

		return h;
	}

	private static JHeader createHeaderInstance(AnnotatedHeader header) {
		try {
			return header.getHeaderClass().newInstance();
		} catch (InstantiationException e) {
			throw new IllegalStateException(e);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		}
	}

	public void setSubHeaders(JHeader[] headers) {
		reorderAndSave(headers);
	}

	public <T extends JSubHeader<B>> T getHeader(T header) {

		final int offset = optionsOffsets[header.getId()];
		final int length = optionsLength[header.getId()];
		header.peer(parent, offset, length);
		header.setOffset(offset);
		header.setLength(length);
		header.setParent(parent);
		header.setPacket(parent.getPacket());

		return header;
	}

	@SuppressWarnings("unchecked")
	public JHeader getHeader(JHeader header) {

		JSubHeader<B> sub = (JSubHeader<B>) header;

		final int id = sub.getId();
		final int offset = optionsOffsets[id];
		final int length = optionsLength[id];
		sub.peer(parent, offset, length);
		sub.setOffset(offset);
		sub.setLength(length);
		sub.setParent(parent);

		return header;
	}

	public JHeader[] getHeaders() {
		List<JHeader> headers = new ArrayList<JHeader>();
		for (int i = 0; i < MAX_HEADERS; i++) {
			if (hasSubHeader(i) && X_HEADERS[i] != null) {
				JHeader header = X_HEADERS[i];
//				parent.getHeader(header); // TODO: fix this
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
			getHeader(header);

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

	public boolean hasHeaders() {
		return this.optionsBitmap != 0;
	}

	private void setHeader(int id, int offset, int length) {
		this.optionsBitmap |= (1L << id);
		this.optionsLength[id] = length;
		this.optionsOffsets[id] = offset;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.newstuff.JHeaderContainer#addHeader(int, int, int)
	 */
	public void addHeader(int id, int offset, int length) {
		if (hasSubHeader(id)) {
			throw new UnsupportedOperationException(
			    "header already set; " +
			    "bitmap header container supports single instances only");
		}
		
		setHeader(id, offset, length);
		count ++;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.newstuff.JHeaderContainer#clear()
	 */
	public void clear() {
		this.optionsBitmap = 0L;
		this.count = 0;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.newstuff.JHeaderContainer#getHeader(org.jnetpcap.packet.JHeader,
	 *      int)
	 */
	public <T extends JSubHeader<B>> T getHeader(T header, int instance) {
		if (instance > 1) {
			throw new UnsupportedOperationException(
			    "header already set; " +
			    "bitmap header container supports single instances only");
		}
		
		return getHeader(header);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.newstuff.JHeaderContainer#getHeaderByIndex(org.jnetpcap.packet.JHeader,
	 *      int)
	 */
	public JHeader getHeaderByIndex(JHeader header, int index) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Not implemented yet");
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.newstuff.JHeaderContainer#getHeaderCount()
	 */
	public int getHeaderCount() {
		return this.count;
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.newstuff.JHeaderContainer#hasHeader(int, int)
	 */
	public boolean hasHeader(int id, int instance) {
		if (instance > 1) {
			return false;
		}
		
		return hasHeader(id);
	}

	/* (non-Javadoc)
   * @see org.jnetpcap.newstuff.JHeaderContainer#getHeader(org.jnetpcap.packet.JHeader, int)
   */
  public B getHeader(B header, int instance) {
	  // TODO Auto-generated method stub
	  throw new UnsupportedOperationException("Not implemented yet");
  }

	/* (non-Javadoc)
   * @see org.jnetpcap.newstuff.JHeaderContainer#hasHeader(int)
   */
  public boolean hasHeader(int id) {
	  // TODO Auto-generated method stub
	  throw new UnsupportedOperationException("Not implemented yet");
  }

	/* (non-Javadoc)
   * @see org.jnetpcap.newstuff.JHeaderContainer#hasHeader(org.jnetpcap.packet.JHeader)
   */
  public boolean hasHeader(B header) {
	  // TODO Auto-generated method stub
	  throw new UnsupportedOperationException("Not implemented yet");
  }



}
