/**
 * Copyright (C) 2008 Sly Technologies, Inc.
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
package org.jnetpcap.packet.format;

import java.util.ArrayList;
import java.util.List;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 *
 */
public class FormatUtils {

	private final static List<String> multiLineStringList =
      new ArrayList<String>();
	private static final String NEWLINE_CHAR = "\n";
	private static final String SPACE_CHAR = " ";
	static String[] table = new String[256];

	static {
  
  	for (int i = 0; i < 31; i++) {
  		table[i] = "\\" + Integer.toHexString(i);
  		if (table[i].length() == 2)
  			table[i] += " ";
  	}
  
  	for (int i = 31; i < 127; i++)
  		table[i] = new String(new byte[] {
  		    (byte) i,
  		    ' ',
  		    ' ' });
  
  	for (int i = 127; i < 256; i++) {
  		table[i] = "\\" + Integer.toHexString(i);
  		if (table[i].length() == 2)
  			table[i] += " ";
  	}
  
  	table[0] = "\\0 ";
  	table[7] = "\\a ";
  	table[11] = "\\v ";
  	table['\b'] = "\\b ";
  	table['\t'] = "\\t ";
  	table['\n'] = "\\n ";
  	table['\f'] = "\\f ";
  	table['\r'] = "\\r ";
  }

	/**
   * @param bs
   * @return
   */
  @SuppressWarnings("unused")
  public static String asString(byte[] bs) {
  	return asString(bs, ':');
  }

	/**
   * @param a
   * @param separator
   * @return
   */
  public static String asString(byte[] a, char separator) {
  	StringBuilder buf = new StringBuilder();
  	for (byte b : a) {
  		if (buf.length() != 0) {
  			buf.append(separator);
  		}
  
  		if (b >= 0 && b < 16) {
  			buf.append('0');
  		}
  
  		buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
  	}
  
  	return buf.toString();
  }

	/**
   * @param a
   * @param separator
   * @param radix
   * @return
   */
  public static String asString(byte[] a, char separator, int radix) {
  	StringBuilder buf = new StringBuilder();
  	for (byte b : a) {
  		if (buf.length() != 0) {
  			buf.append(separator);
  		}
  		if (radix == 16) {
  			buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
  		} else {
  			buf.append(Integer.toString((b < 0) ? b + 256 : b).toUpperCase());
  
  		}
  	}
  
  	return buf.toString();
  }

	/**
   * Handles various forms of ip6 addressing
   * 
   * <pre>
   *  2001:0db8:0000:0000:0000:0000:1428:57ab
   * 	2001:0db8:0000:0000:0000::1428:57ab
   * 	2001:0db8:0:0:0:0:1428:57ab
   * 	2001:0db8:0:0::1428:57ab
   * 	2001:0db8::1428:57ab
   * 	2001:db8::1428:57ab
   * </pre>
   * 
   * @param value
   * @param c
   * @return
   */
  public static String asStringIp6(byte[] a, boolean holes) {
  	StringBuilder buf = new StringBuilder();
  
  	int len = 0;
  	int start = -1;
  	/*
  	 * Check for byte compression where sequential zeros are replaced with ::
  	 */
  	for (int i = 0; i < a.length && holes; i++) {
  		if (a[i] == 0) {
  			if (len == 0) {
  				start = i;
  			}
  
  			len++;
  		}
  
  		/*
  		 * Only the first sequence of 0s is compressed, so break out
  		 */
  		if (a[i] != 0 && len != 0) {
  			break;
  		}
  	}
  
  	/*
  	 * Now round off to even length so that only pairs are compressed
  	 */
  	if (start != -1 && (start % 2) == 1) {
  		start++;
  		len--;
  	}
  
  	if (start != -1 && (len % 2) == 1) {
  		len--;
  	}
  
  	for (int i = 0; i < a.length; i++) {
  		if (i == start) {
  			buf.append(':');
  			i += len - 1;
  
  			if (i == a.length - 1) {
  				buf.append(':');
  			}
  			continue;
  		}
  
  		byte b = a[i];
  
  		if (buf.length() != 0 && (i % 2) == 0) {
  			buf.append(':');
  		}
  		if (b < 16) {
  			buf.append('0');
  		}
  		buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
  	}
  
  	return buf.toString();
  }

	/**
   * @param a
   * @param prefix
   * @param indentFirstLine
   * @param addressOffset
   * @param dataOffset
   * @return
   */
  public static String[] hexdump(byte[] a, int addressOffset, int dataOffset,
      boolean doAddress, boolean doText, boolean doData) {
  
  	multiLineStringList.clear();
  
  	for (int i = 0; i + dataOffset < a.length; i += 16) {
  		multiLineStringList.add(hexLine(a, i + addressOffset, i + dataOffset,
  		    doAddress, doText, doData));
  	}
  
  	return multiLineStringList.toArray(new String[multiLineStringList.size()]);
  }

	/**
   * @param a
   * @param address
   * @param i
   * @param doAddress
   * @param doText
   * @return
   */
  public static String hexLine(byte[] a, int address, int i, boolean doAddress,
      boolean doText, boolean doData) {
  	String s = "";
  	if (doAddress) {
  		s += hexLineAddress(address);
  		s += ":" + SPACE_CHAR;
  	}
  
  	if (doData) {
  		s += hexLineData(a, i);
  	}
  
  	if (doText) {
  		s += SPACE_CHAR;
  		s += SPACE_CHAR;
  		s += SPACE_CHAR;
  
  		s += hexLineText(a, i);
  	}
  
  	return (s);
  }

	public static String hexLineAddress(int address) {
  	String s = "";
  
  	s = Integer.toHexString(address);
  
  	for (int i = s.length(); i < 4; i++)
  		s = "0" + s;
  
  	return (s);
  }

	public static String hexLineData(byte[] data, int offset) {
  	String s = "";
  
  	int i = 0;
  	for (i = 0; i + offset < data.length && i < 16; i++) {
  
  		/**
  		 * Insert a space every 4 characaters.
  		 */
  		if (i % 4 == 0 && i != 0)
  			s += SPACE_CHAR;
  
  		s += toHexString(data[i + offset]);
  	}
  
  	/**
  	 * Continue the loop and append spaces to fill in the missing data.
  	 */
  	for (; i < 16; i++) {
  		/**
  		 * Insert a space every 4 characaters.
  		 */
  		if (i % 4 == 0 && i != 0)
  			s += SPACE_CHAR;
  
  		s += SPACE_CHAR + SPACE_CHAR;
  	}
  
  	return (s);
  }

	public static String hexLineText(byte[] data, int offset) {
  
  	String s = "";
  
  	int i;
  	for (i = 0; i + offset < data.length && i < 16; i++) {
  		s += table[data[i + offset] & 0xFF];
  
  		// if(Character.isLetterOrDigit(table[data[i + offset] & 0xFF]) ||
  		// (table[data[i + offset] & 0xFF]) == ' ')
  		// s += " " + table[data[i + offset] & 0xFF];
  		// else
  		// s += " " + NONPRINTABLE_CHAR;
  	}
  
  	/**
  	 * Continue the loop and fill in any missing data less than 16 bytes.
  	 */
  	for (; i < 16; i++) {
  		s += SPACE_CHAR;
  	}
  
  	return (s);
  }

	/**
  	 * @param pkt_data
  	 * @return
  	 */
  	public static byte[] toByteArray(String pkt_data) {
  
  		String s = pkt_data.replaceAll(" |\n", "");
  
  		byte[] b = new byte[s.length() / 2];
  
  		if ((s.length() % 2) != 0) {
  			System.err.println(s);
  			throw new IllegalArgumentException(
  			    "need even number of hex double digits [" + s.length() + "]");
  		}
  
  		for (int i = 0; i < s.length(); i += 2) {
  			String q = s.substring(i, i + 2);
  //			System.out.print(q);
  			b[i / 2] = (byte)Integer.parseInt(q, 16);
  		}
  
  		return b;
  	}

	public static String toHexString(byte b) {
  	String s = Integer.toHexString(((int) b) & 0xFF);
  
  	if (s.length() == 1)
  		return ("0" + s);
  
  	return (s);
  }

}
