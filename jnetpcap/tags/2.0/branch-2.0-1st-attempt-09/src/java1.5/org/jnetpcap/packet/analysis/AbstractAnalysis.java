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

import java.nio.ByteOrder;
import java.util.Iterator;

import org.jnetpcap.nio.JMemory;
import org.jnetpcap.nio.JStructBuffer;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class AbstractAnalysis<S extends JAnalysis, E extends AnalyzerEvent>
    extends JStructBuffer implements JAnalysis {

	private enum Field implements JStructField {
		TYPE,
		TITLE(REF),
		TEXT(REF),
		ANALYZER(REF),
		LISTENERS(REF), ;


		private final int len;

		int offset;

		private Field() {
			this(4);
		}

		private Field(int len) {
			this.len = len;
		}

		public int length(int offset) {
			this.offset = offset;
			return this.len;
		}

		public final int offset() {
			return offset;
		}
	}

	private final int type;

	public AbstractAnalysis(Type type) {
		super(type);

		this.type = AnalysisUtils.getType(getClass());
	}

	public AbstractAnalysis(JStructField... c) {
		this((String) null, c);
	}
//
//	@SuppressWarnings("unchecked")
//	public <T extends Enum<T> & JStructField> AbstractAnalysis(Class<T> c1,
//	    Class<T> c2) {
//		this((String) null, (Class<T>) Field.class, c1, c2);
//	}
//
//	@SuppressWarnings("unchecked")
//	public <T extends Enum<T> & JStructField> AbstractAnalysis(Class<T> c1,
//	    Class<T> c2, Class<T> c3) {
//		this((String) null, (Class<T>) Field.class, c1, c2, c3);
//	}

	public AbstractAnalysis(String title, JStructField... fields) {

		super(Field.values(), fields);

		setTitle(title == null ? getClass().getSimpleName() : title);
		setText(new String[0]);

		super.order(ByteOrder.nativeOrder());

		/*
		 * We set a local type field and the native type in buffer. Native type is
		 * needed by native analyzers.
		 */
		this.type = AnalysisUtils.getType(getClass());
		setType(AnalysisUtils.getType(getClass()));
	}

	public <U> boolean addListener(AnalyzerListener<E> listener, U user) {
		if (getSupport() == null) {
			setSupport(new AnalyzerSupport<E>());
		}
		return getSupport().addListener(listener, user);
	}

	public <T extends JAnalysis> T getAnalysis(T analysis) {
		return null;
	}

	protected JAnalyzer getAnalyzer() {
		return getObject(JAnalyzer.class, Field.ANALYZER.offset());
	}

	@SuppressWarnings("unchecked")
	protected AnalyzerSupport<E> getSupport() {
		return getObject(AnalyzerSupport.class, Field.LISTENERS.offset());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.analysis.JAnalysis#getCategory()
	 */
	public int getType() {
		return this.type;
	}

	public <T extends JAnalysis> boolean hasAnalysis(T analysis) {
		return hasAnalysis(analysis.getType());
	}

	public <T extends JAnalysis> boolean hasAnalysis(Class<T> analysis) {
		return hasAnalysis(AnalysisUtils.getType(analysis));
	}

	public boolean hasAnalysis(int type) {
		return getType() == type;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.analysis.JAnalysis#peer(org.jnetpcap.packet.analysis.JAnalysis)
	 */
	public int peer(JAnalysis peer) {
		return (getType() == peer.getType()) ? super.peer((JMemory) peer) : 0;
	}

	public boolean removeListener(AnalyzerListener<E> listener) {
		return (getSupport() == null) ? false : getSupport().removeListener(
		    listener);
	}

	public void setAnalyzer(JAnalyzer analyzer) {
		setObject(Field.ANALYZER.offset(), analyzer);
	}

	private void setSupport(AnalyzerSupport<E> support) {
		setObject(Field.LISTENERS.offset(), support);
	}

	private void setType(int type) {
		setInt(Field.TYPE.offset(), type);
	}

	public Iterator<JAnalysis> iterator() {
		return AnalysisUtils.EMPTY_ITERATOR;
	}

	public String getTitle() {
		return getObject(String.class, Field.TITLE.offset());
	}

	private void setTitle(String title) {
		setObject(Field.TITLE.offset(), title);
	}

	public String[] getText() {
		return getObject(String[].class, Field.TEXT.offset());
	}

	public void setText(String[] text) {
		setObject(Field.TEXT.offset(), text);
	}
}
