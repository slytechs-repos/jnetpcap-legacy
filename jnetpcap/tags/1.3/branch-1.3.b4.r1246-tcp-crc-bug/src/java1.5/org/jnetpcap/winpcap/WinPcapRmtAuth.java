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
package org.jnetpcap.winpcap;

// TODO: Auto-generated Javadoc
/**
 * The Class WinPcapRmtAuth.
 */
public final class WinPcapRmtAuth {

	/** The Constant RMT_AUTH_NULL. */
	public final static int RMT_AUTH_NULL = 0;

	/** The Constant RMT_AUTH_PWD. */
	public final static int RMT_AUTH_PWD = 1;

	/**
	 * Inits the i ds.
	 */
	private native static void initIDs();

	static {
		initIDs();
	}

	/** The type. */
	private int type;

	/** The username. */
	private String username;

	/** The password. */
	private String password;

	/**
	 * Instantiates a new win pcap rmt auth.
	 */
	public WinPcapRmtAuth() {

	}

	/**
	 * Instantiates a new win pcap rmt auth.
	 * 
	 * @param type
	 *          the type
	 * @param username
	 *          the username
	 * @param password
	 *          the password
	 */
	public WinPcapRmtAuth(int type, String username, String password) {
		this.type = type;
		this.username = username;
		this.password = password;
	}

	/**
	 * Gets the type.
	 * 
	 * @return the type
	 */
	public final int getType() {
		return this.type;
	}

	/**
	 * Sets the type.
	 * 
	 * @param type
	 *          the new type
	 */
	public final void setType(int type) {
		this.type = type;
	}

	/**
	 * Gets the username.
	 * 
	 * @return the username
	 */
	public final String getUsername() {
		return this.username;
	}

	/**
	 * Sets the username.
	 * 
	 * @param username
	 *          the new username
	 */
	public final void setUsername(String username) {
		this.username = username;
	}

	/**
	 * Gets the password.
	 * 
	 * @return the password
	 */
	public final String getPassword() {
		return this.password;
	}

	/**
	 * Sets the password.
	 * 
	 * @param password
	 *          the new password
	 */
	public final void setPassword(String password) {
		this.password = password;
	}

}
