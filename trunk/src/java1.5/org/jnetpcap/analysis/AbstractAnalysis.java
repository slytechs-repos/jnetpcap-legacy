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

import java.nio.ByteOrder;
import java.util.Iterator;

import org.jnetpcap.nio.JMemory;
import org.jnetpcap.nio.JObjectBuffer;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class AbstractAnalysis<S extends JAnalysis, E extends AnalyzerEvent>
    extends JObjectBuffer implements JAnalysis {

	/**
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public interface AnalysisField {

		public int getLength();

		public int getOffset();

	}

	private final static int ANALYZER = 4 + REF;

	private final static int CATEGORY = 0;

	private final static int LISTENERS = 4;

	private final static int SIZE = REF * 2 + 4;

	private final int offset;

	private final String name;

	private String nicname;

	private int type;

	public AbstractAnalysis(Type type, int size) {
		this(type, size, null);
	}

	public AbstractAnalysis(int size) {
		this(size, null);
	}

	public AbstractAnalysis(int size, String name) {
		super(SIZE + size);
		this.offset = size;
		this.name = name == null ? getClass().getSimpleName() : name;
		this.nicname = name;

		super.order(ByteOrder.nativeOrder());

		/*
		 * We set a local type field and the native type in buffer. Native type is
		 * needed by native analyzers.
		 */
		setType(AnalysisUtils.getType(getClass()));
		this.type = AnalysisUtils.getType(getClass());

	}

	/**
	 * Peered constructor
	 * 
	 * @param pointer
	 * @param i
	 * @param name
	 */
	public AbstractAnalysis(Type type, int size, String name) {
		super(type);
		this.offset = size;
		this.name = name == null ? getClass().getSimpleName() : name;
		this.nicname = name;
		this.type = AnalysisUtils.getType(getClass());

		super.order(ByteOrder.nativeOrder());
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

	public JAnalyzer getAnalyzer() {
		return getObject(JAnalyzer.class, offset + ANALYZER);
	}

	@SuppressWarnings("unchecked")
	private AnalyzerSupport<E> getSupport() {
		return getObject(AnalyzerSupport.class, offset + LISTENERS);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.JAnalysis#getCategory()
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
		return this.type == type;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.JAnalysis#peer(org.jnetpcap.analysis.JAnalysis)
	 */
	public int peer(JAnalysis peer) {
		return (getType() == peer.getType()) ? super.peer((JMemory) peer) : 0;
	}

	public boolean removeListener(AnalyzerListener<E> listener) {
		return (getSupport() == null) ? false : getSupport().removeListener(
		    listener);
	}

	public void setAnalyzer(JAnalyzer analyzer) {
		setObject(offset + ANALYZER, analyzer);
	}

	private void setSupport(AnalyzerSupport<E> support) {
		setObject(offset + LISTENERS, support);
	}

	private void setType(int type) {
		setInt(CATEGORY, type);

	}

	public Iterator<JAnalysis> iterator() {
		return AnalysisUtils.EMPTY_ITERATOR;
	}

	public String getTitle() {
		return this.name;
	}

	public String[] getText() {
		return null;
	}

	public String getShortTitle() {
		return nicname;
	}

}
