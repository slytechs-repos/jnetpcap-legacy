/*
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010 Sly Technologies, Inc.
 *
 * This file is part of jNetPcap.
 *
 * jNetPcap is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as 
 * published by the Free Software Foundation, either version 3 of 
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.jnetpcap.packet;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JFlowMap
    extends HashMap<JFlowKey, JFlow> implements PcapPacketHandler<Object> {

	/**
	 * 
	 */
	private static final long serialVersionUID = -5590314946675005059L;
	
	/**
	 * Total packet count added.
	 */
	private int count = 0;

	/**
	 * 
	 */
	public JFlowMap() {
	}

	/**
	 * @param initialCapacity
	 */
	public JFlowMap(int initialCapacity) {
		super(initialCapacity);
	}

	/**
	 * @param m
	 */
	public JFlowMap(Map<? extends JFlowKey, ? extends JFlow> m) {
		super(m);
	}

	/**
	 * @param initialCapacity
	 * @param loadFactor
	 */
	public JFlowMap(int initialCapacity, float loadFactor) {
		super(initialCapacity, loadFactor);
	}

	/* (non-Javadoc)
   * @see org.jnetpcap.packet.JPacketHandler#nextPacket(org.jnetpcap.packet.JPacket, java.lang.Object)
   */
  public void nextPacket(PcapPacket packet, Object user) {
  	packet = new PcapPacket(packet); // make a copy
  	JFlowKey key = packet.getState().getFlowKey();
  	
		JFlow flow = super.get(key);
  	if (flow == null) {
  		flow = new JFlow(new PcapPacket(packet).getState().getFlowKey());
  		super.put(key, flow);
  	}
  	
		flow.add(packet);
		count ++;
  }
  
  public int getTotalPacketCount() {
  	return count;
  }

  public String toString() {
  	StringBuilder b = new StringBuilder(1024 * 50);
  	
  	b.append("total packet count=").append(count).append("\n");
  	b.append("total flow count=").append(size()).append("\n");
  	
  	int i = 0;
  	for (JFlow flow: values()) {
  		b.append("flow[").append(i++).append(']').append(' ');
  		b.append(flow.toString());
  		b.append(",\n");
  	}
  	
  	return b.toString();
  }
  
}
