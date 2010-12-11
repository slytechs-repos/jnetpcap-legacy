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

// TODO: Auto-generated Javadoc
/**
 * The Interface JHeaderAccessor.
 */
public interface JHeaderAccessor {

	/**
	 * Gets the header.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param header
	 *          the header
	 * @return the header
	 */
	public <T extends JHeader> T getHeader(T header);

	/**
	 * Gets the header.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param header
	 *          the header
	 * @param instance
	 *          the instance
	 * @return the header
	 */
	public <T extends JHeader> T getHeader(T header, int instance);

	/**
	 * Gets the header by index.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param index
	 *          the index
	 * @param header
	 *          the header
	 * @return the header by index
	 */
	public <T extends JHeader> T getHeaderByIndex(int index, T header);

	/**
	 * Gets the header count.
	 * 
	 * @return the header count
	 */
	public int getHeaderCount();

	/**
	 * Gets the header id by index.
	 * 
	 * @param index
	 *          the index
	 * @return the header id by index
	 */
	public int getHeaderIdByIndex(int index);

	/**
	 * Gets the header instance count.
	 * 
	 * @param id
	 *          the id
	 * @return the header instance count
	 */
	public int getHeaderInstanceCount(int id);

	/**
	 * Checks for header.
	 * 
	 * @param id
	 *          the id
	 * @return true, if successful
	 */
	public boolean hasHeader(int id);

	/**
	 * Checks for header.
	 * 
	 * @param id
	 *          the id
	 * @param instance
	 *          the instance
	 * @return true, if successful
	 */
	public boolean hasHeader(int id, int instance);

	/**
	 * Checks for header.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param header
	 *          the header
	 * @return true, if successful
	 */
	public <T extends JHeader> boolean hasHeader(T header);

	/**
	 * Checks for header.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param header
	 *          the header
	 * @param instance
	 *          the instance
	 * @return true, if successful
	 */
	public <T extends JHeader> boolean hasHeader(T header, int instance);
}
