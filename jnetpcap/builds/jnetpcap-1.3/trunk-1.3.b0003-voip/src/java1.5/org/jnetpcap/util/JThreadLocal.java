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
package org.jnetpcap.util;

import java.lang.reflect.Constructor;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 *
 */
public class JThreadLocal<T>
    extends ThreadLocal<T> {

	private final Constructor<T> constructor;

	/**
	 * 
	 */
	public JThreadLocal() {
		super();
		constructor = null;
	}
	
	public JThreadLocal(Class<T> c) {
		try {
	    constructor = c.getConstructor();
    } catch (Exception e) {
    	throw new IllegalArgumentException(e);
    } 
	}

	@Override
  protected T initialValue() {
		if (constructor == null) {
			return super.initialValue();
		} else {
			try {
	      return constructor.newInstance();
      } catch (Exception e) {
      	throw new IllegalStateException(e);
      }
		}
  }

}
