/**
 * Copyright (C) 2009 Sly Technologies, Inc.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package org.jnetpcap.analysis;

import java.util.ArrayList;
import java.util.List;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 *
 */
public class AnalysisUtils {
	
	@SuppressWarnings("unused")
  private static class RootAnalysis {		
	};
	
	/**
	 * Type for native root analysis objects. These are the root analysis objects
	 * attached to packet and header states. 
	 */
  public final static int ROOT_TYPE = 0;
	
  /**
   * Our allocation mechanism for types. 
   */
	private final static List<Class<?>> types;
	
	static {
		types = new ArrayList<Class<?>>(256);
		types.add(RootAnalysis.class); // Reserved for ROOT_TYPE
	}
	
	public static int getType(Class<?> c) {
		int index = types.indexOf(c);
		if (index == -1) {
			index = types.size();
			types.add(c);
		}
		
		return index;
	}

}
