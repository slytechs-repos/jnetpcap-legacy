/**
 * 
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
