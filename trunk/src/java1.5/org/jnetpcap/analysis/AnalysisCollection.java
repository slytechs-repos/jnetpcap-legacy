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

import java.util.HashMap;
import java.util.Map;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class AnalysisCollection implements JAnalysis {

	private Map<Class<? extends JAnalysis>, JAnalysis> map =
	    new HashMap<Class<? extends JAnalysis>, JAnalysis>();

	private final int category = AnalysisUtils.getType(getClass());

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.JAnalysis#hasAnalysis(java.lang.Class)
	 */
	public boolean hasAnalysis(Class<? extends JAnalysis> analysis) {
		return map.containsKey(analysis.getClass());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.JAnalysis#getAnalysis(java.lang.Class)
	 */
	@SuppressWarnings("unchecked")
	public <T extends JAnalysis> T getAnalysis(Class<T> analysis) {
		return (T) map.get(analysis.getClass());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.JAnalysis#getCategory()
	 */
	public int getType() {
		return this.category;
	}

}
