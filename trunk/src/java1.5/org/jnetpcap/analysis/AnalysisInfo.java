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

import java.util.Iterator;

/**
 * Analysis information. Provides general information used by formatters to
 * displays about the details of the analysis.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class AnalysisInfo implements JAnalysis {

	private final String nicname;

	private final String summary;

	private final String name;

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.JAnalysis#getAnalysis(org.jnetpcap.analysis.JAnalysis)
	 */
	public <T extends JAnalysis> T getAnalysis(T analysis) {
		return null;
	}

	/**
	 * @param name
	 * @param nicname
	 * @param summary
	 */
	public AnalysisInfo(String name, String nicname, String summary) {
		this.name = name;
		this.nicname = nicname;
		this.summary = summary;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.JAnalysis#getName()
	 */
	public String getName() {
		return name;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.JAnalysis#getNicName()
	 */
	public String getNicName() {
		return nicname;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.JAnalysis#getSummary()
	 */
	public Object getSummary() {
		return summary;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.JAnalysis#getType()
	 */
	public int getType() {
		return AnalysisUtils.INFO_TYPE;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.JAnalysis#hasAnalysis(org.jnetpcap.analysis.JAnalysis)
	 */
	public <T extends JAnalysis> boolean hasAnalysis(T analysis) {
		return false;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.JAnalysis#hasAnalysis(java.lang.Class)
	 */
	public <T extends JAnalysis> boolean hasAnalysis(Class<T> analysis) {
		return false;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.JAnalysis#hasAnalysis(int)
	 */
	public boolean hasAnalysis(int type) {
		return false;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.JAnalysis#peer(org.jnetpcap.analysis.JAnalysis)
	 */
	public int peer(JAnalysis peer) {
		return 0;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Iterable#iterator()
	 */
	public Iterator<JAnalysis> iterator() {
		return AnalysisUtils.EMPTY_ITERATOR;
	}
}
