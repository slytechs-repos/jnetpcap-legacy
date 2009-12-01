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
package org.jnetpcap.util;

import java.io.IOException;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class RateMeasurement
    extends
    Measurement {

	long ts;

	long te;

	private float rate;

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.util.Measurement#report(java.lang.Appendable)
	 */
	@Override
	public void report(Appendable out) throws IOException {
		calcRate();
		
		out.append(Float.toString(rate));
	}

	private void calcRate() {
		this.te = System.currentTimeMillis();

		rate = ((float) counter) / (te - ts);
	}
	
  public void snapshot() {
    super.snapshot();
    
  	this.ts = System.currentTimeMillis();
  	this.te = this.ts;
  }


	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.util.Measurement#reset()
	 */
	@Override
	public void reset() {
		this.counter = 0;
		this.total = 0;
		this.ts = System.currentTimeMillis();
		this.te = ts;
		this.rate = 0f;
	}

}
