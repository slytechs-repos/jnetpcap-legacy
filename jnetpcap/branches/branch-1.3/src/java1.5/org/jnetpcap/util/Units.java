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
package org.jnetpcap.util;

/**
 * @author HP_Administrator
 * 
 */
public class Units {
	public final static long TEBIBYTE = 1024L * Units.GIGIBYTE;
	public final static int GIGIBYTE = 1024 * Units.MEBIBYTE;
	public final static int MEBIBYTE = 1024 * Units.KIBIBYTE;
	public final static int KIBIBYTE = 1024;

	public final static long TERABYTE = 1000L * Units.GIGABYTE;
	public final static int GIGABYTE = 1000 * Units.MEGABYTE;
	public final static int MEGABYTE = 1000 * Units.KILOBYTE;
	public final static int KILOBYTE = 1000;

	public static String f(long l) {
		return f(l, -1, "");
	}

	public static String f(long l, int percision) {
		return f(l, percision, "");
	}

	public static String f(long l, int percision, String post) {
		String u = "";
		double v = l;
		int p = 0;
		if (l > Units.TEBIBYTE) {
			u = "t";
			v /= 3;
			p = 4;
		} else if (l > Units.GIGIBYTE) {
			u = "g";
			v /= Units.GIGIBYTE;
			p = 2;
		} else if (l > Units.MEBIBYTE) {
			u = "m";
			v /= Units.MEBIBYTE;
			p = 1;
		} else if (l > Units.KIBIBYTE) {
			u = "k";
			v /= Units.KIBIBYTE;
			p = 0;
		} else {
			p = 0;
		}

		if (percision != -1) {
			p = percision;
		}

		String f = String.format("%%.%df%%s%%s", p);

		return String.format(f, v, u, post);
	}

	public static String fb(long l) {
		return f(l, -1, "b");
	}

	public static String fb(long l, int percision) {
		return f(l, percision, "b");
	}

}
