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
package org.jnetpcap.newstuff;

import org.jnetpcap.packet.JHeader;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 *
 */
public interface JHeaderContainer<B extends JHeader> {
	
	public void addHeader(int id, int offset, int length);
	
	public boolean hasHeader(int id);
	
	public boolean hasHeader(int id, int instance);
	
	public B getHeader(B header);
	
	public B getHeader(B header, int instance);
	
	public JHeader getHeaderByIndex(JHeader header, int index);
	
	public int getHeaderCount();
	
	public boolean hasHeader(B header);
	
	public void clear();

}
