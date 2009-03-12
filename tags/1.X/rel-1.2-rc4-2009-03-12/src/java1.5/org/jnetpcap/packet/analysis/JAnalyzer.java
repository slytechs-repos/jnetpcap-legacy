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
package org.jnetpcap.packet.analysis;

import java.util.Queue;

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.util.TimeoutQueue;


/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 *
 */
public interface JAnalyzer {

	/**
   * @param packet
	 * @throws AnalyzerException 
   */
  public boolean processPacket(JPacket packet) throws AnalysisException;

	/**
   * @return
   */
  public int getPriority();
  
  public void setParent(JAnalyzer parent);
  
  public Queue<JPacket> getInQueue();
  
  public Queue<JPacket> getOutQueue();

	/**
   * @return
   */
  public TimeoutQueue getTimeoutQueue();
  
  public long getProcessingTime();
  
  public int hold();
  
  public int release();

  public boolean processHeaders(JPacket packet, long map);

	/**
   * @param packet
   * @return
   */
  public boolean processHeaders(JPacket packet);
  
  public void consumePacket(JPacket packet);
}
