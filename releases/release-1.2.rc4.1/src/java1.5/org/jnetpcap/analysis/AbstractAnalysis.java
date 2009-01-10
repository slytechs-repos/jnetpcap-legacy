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

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class AbstractAnalysis<S extends JAnalysis, E extends AnalyzerEvent>
    implements JAnalysis {

	private final int category;

	private AnalyzerSupport<E> listeners = null;

	private JAnalyzer analyzer;

	public AbstractAnalysis() {
		this.category = AnalysisUtils.getType(getClass());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.JAnalysis#getAnalysis(java.lang.Class)
	 */
	public <T extends JAnalysis> T getAnalysis(Class<T> analysis) {
		return null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.JAnalysis#getCategory()
	 */
	public int getType() {
		return this.category;
	}

	public <U> boolean addListener(AnalyzerListener<E> listener, U user) {
		if (listeners == null) {
			listeners = new AnalyzerSupport<E>();
		}
		return this.listeners.addListener(listener, user);
	}

	public boolean removeListener(AnalyzerListener<E> listener) {
		return (listeners == null) ? false : this.listeners
		    .removeListener(listener);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.JAnalysis#hasAnalysis(java.lang.Class)
	 */
	public boolean hasAnalysis(Class<? extends JAnalysis> analysis) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Not implemented yet");
	}
}
