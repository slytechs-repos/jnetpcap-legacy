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

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JAnalysisMap
    extends AbstractAnalysis<JAnalysisMap, AnalyzerEvent> implements JAnalysis {

	public final static int TYPE = AnalysisUtils.CONTAINER_TYPE;

	private final static int MAP = 0; // offset
	
	private enum Field implements JStructField {
		;
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

	public JAnalysisMap() {
		super(Field.values());

		super.setObject(MAP, new HashMap<Integer, JAnalysis>());
	}

	@SuppressWarnings("unchecked")
	private Map<Integer, JAnalysis> getMap() {
		return getObject(Map.class, MAP);
	}
	
	public void add(JAnalysis analysis) {
		getMap().put(analysis.getType(), analysis);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.analysis.JPeerableAnalysis#getAnalysis(org.jnetpcap.packet.analysis.JPeerableAnalysis)
	 */
	public <T extends JAnalysis> T getAnalysis(T analysis) {
		JAnalysis a = getMap().get(analysis.getType());
		analysis.peer(a);

		return analysis;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.analysis.JPeerableAnalysis#hasAnalysis(org.jnetpcap.packet.analysis.JPeerableAnalysis)
	 */
	public <T extends JAnalysis> boolean hasAnalysis(T analysis) {
		if (getMap().containsKey(analysis.getType())) {
			getAnalysis(analysis); // Do the peering

			return true;
		} else {
			return false;
		}
	}

	@Override
	public boolean hasAnalysis(int type) {
		return getMap().containsKey(type);
	}

	public Iterator<JAnalysis> iterator() {
		final Iterator<JAnalysis> i = getMap().values().iterator();
		
		return i;
		
//		return new Iterator<JAnalysis>() {
//			JAnalysis main = null;
//			Iterator<JAnalysis> s = null;
//
//			public boolean hasNext() {
//				if (main == null && (s == null || s.hasNext() == false)) {
//					if (i.hasNext()) {
//						main = i.next();
//						s = main.iterator();
//						
//					} else {
//						return false;
//					}
//				}
//				
//				return main != null || s.hasNext();
//      }
//
//			public JAnalysis next() {
//				JAnalysis a = (main == null) ? s.next() : main;
//			
//				if (main != null) { 
//					main = null;
//				}
//				
//				return a;
//      }
//
//			public void remove() {
//	      throw new UnsupportedOperationException("Not implemented yet");
//      }
//			
//		};
  }
	
	
}
