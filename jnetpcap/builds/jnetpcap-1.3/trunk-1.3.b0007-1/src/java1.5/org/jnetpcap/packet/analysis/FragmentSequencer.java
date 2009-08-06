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

import java.util.List;

public interface FragmentSequencer extends JAnalyzer {

	/**
   * The default timeout interval in millis for a fragment sequence completion.
   */
  public static final int DEFAULT_FRAGMENT_TIMEOUT = 60 * 1000;
	public final FragmentAssembly reassembly = new FragmentAssembly();

	/**
	 * Signal to analyzer that this fragment sequence has expired
	 * 
	 * @param analysis
	 *          sequence which expired
	 */
	public void timeout(FragmentSequence analysis);

	/**
	 * Allows an analyzer to generate analyzer specific information to be
	 * displayed by formatters.
	 * 
	 * @return list typically made up of AnalysisInfo objects
	 */
	public List<JAnalysis> generateInfo(FragmentSequence sequence);

}