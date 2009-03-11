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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class AnalysisUtils {

	public final static Iterator<JAnalysis> EMPTY_ITERATOR =
	    new Iterator<JAnalysis>() {

		    public boolean hasNext() {
			    return false;
		    }

		    public JAnalysis next() {
			    throw new UnsupportedOperationException("Not implemented yet");
		    }

		    public void remove() {
			    throw new UnsupportedOperationException("Not implemented yet");
		    }

	    };

	public final static Iterable<JAnalysis> EMPTY_ITERABLE =
	    new Iterable<JAnalysis>() {

		    public Iterator<JAnalysis> iterator() {
			    return AnalysisUtils.EMPTY_ITERATOR;
		    }

	    };

	@SuppressWarnings("unused")
	private static class RootAnalysis {
	};

	/**
	 * Type for native root analysis objects. These are the root analysis objects
	 * attached to packet and header states.
	 */
	public final static int ROOT_TYPE = 1;

	/**
	 * Our allocation mechanism for types.
	 */
	private final static List<Class<?>> types;

	public static final int CONTAINER_TYPE = 2;

	public static final int INFO_TYPE = 0;

	static {
		types = new ArrayList<Class<?>>(256);
		types.add(AnalysisInfo.class); // Reserved
		types.add(RootAnalysis.class); // Reserved
		types.add(JAnalysisMap.class); // Reserved
	}

	public static int getType(Class<?> c) {
		int index = types.indexOf(c);
		if (index == -1) {
			index = types.size();
			types.add(c);
		}

		return index;
	}

	/**
	 * @param container
	 * @param analysis
	 */
	public static void addAnalysis(JAnalysis container, JAnalysis analysis) {
		if (container instanceof JAnalysisMap) {
			JAnalysisMap map = (JAnalysisMap) container;
			map.add(analysis);
		}
	}

	/**
	 * @return
	 */
	public static JAnalysis createContainer() {
		return new JAnalysisMap();
	}

	/**
	 * @param packetState
	 * @param headerState
	 * @param analysis
	 */
	public static void addToRoot(
	    JPacket.State packetState,
	    JHeader.State headerState,
	    JAnalysis analysis) {
		JAnalysis a = headerState.getAnalysis();
		if (a == null) {
			headerState.setAnalysis(packetState, analysis);
			return;
		}

		if (a.getType() == AnalysisUtils.CONTAINER_TYPE) {
			AnalysisUtils.addAnalysis(a, analysis);
			return;
		}

		JAnalysis container = AnalysisUtils.createContainer();
		headerState.setAnalysis(packetState, container);

		AnalysisUtils.addAnalysis(container, a);
		AnalysisUtils.addAnalysis(container, analysis);
	}

	/**
	 * @param analysis
	 * @return
	 */
	public static Iterable<JAnalysis> toIterable(final JAnalysis analysis) {
		return (analysis == null)?EMPTY_ITERABLE : new Iterable<JAnalysis>() {

			public Iterator<JAnalysis> iterator() {
				return new Iterator<JAnalysis>() {
					
					private boolean hasNext = true;

					public boolean hasNext() {
						if (hasNext) {
							hasNext = false;
							return true;
						}
						
						return false;
          }

					public JAnalysis next() {
						return analysis;
          }

					public void remove() {
	          throw new UnsupportedOperationException("Not supported");
          }
					
				};
      }
			
		};
	}

}
