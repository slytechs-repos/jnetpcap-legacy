/**
 * Copyright (C) 2007 Sly Technologies, Inc. This library is free software; you
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
package org.jnetpcap.winpcap;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public final class WinPcapRmtAuth {

	/**
	 * It defines the NULL authentication. This value has to be used within the
	 * 'type' member of the pcap_rmtauth structure. The 'NULL' authentication has
	 * to be equal to 'zero', so that old applications can just put every field of
	 * struct pcap_rmtauth to zero, and it does work.
	 */
	public final static int RMT_AUTH_NULL = 0;

	/**
	 * It defines the username/password authentication. With this type of
	 * authentication, the RPCAP protocol will use the username/ password provided
	 * to authenticate the user on the remote machine. If the authentication is
	 * successful (and the user has the right to open network devices) the RPCAP
	 * connection will continue; otherwise it will be dropped. This value has to
	 * be used within the 'type' member of the pcap_rmtauth structure.
	 */
	public final static int RMT_AUTH_PWD = 1;

	private native static void initIDs();

	static {
		initIDs();
	}

	private int type;

	private String username;

	private String password;

	/**
	 * @return the type
	 */
	public final int getType() {
		return this.type;
	}

	/**
	 * @param type
	 *          the type to set
	 */
	public final void setType(int type) {
		this.type = type;
	}

	/**
	 * @return the username
	 */
	public final String getUsername() {
		return this.username;
	}

	/**
	 * @param username
	 *          the username to set
	 */
	public final void setUsername(String username) {
		this.username = username;
	}

	/**
	 * @return the password
	 */
	public final String getPassword() {
		return this.password;
	}

	/**
	 * @param password
	 *          the password to set
	 */
	public final void setPassword(String password) {
		this.password = password;
	}

}
