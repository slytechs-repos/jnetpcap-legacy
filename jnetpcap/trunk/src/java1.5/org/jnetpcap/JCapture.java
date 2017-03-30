/**
 *  All code (c)2005-2017 Sly Technologies Inc. all rights reserved
 */
package org.jnetpcap;

import java.util.concurrent.TimeUnit;

// TODO: Auto-generated Javadoc
/**
 * Interface used to abstract pcap callback method. JCapture is used to extend
 * pcap with new callback implementations.
 *
 * @author Sly Technologies Inc.
 * @param <T>
 *            the generic type
 */
public abstract class JCapture<H extends JHandler<T>, T> {

	final int capture(Pcap pcap, int cnt, H handler, T user, long timeout, TimeUnit unit) {
		return doCapture(pcap, cnt, handler, user, timeout, unit);
	}

	final int capture(Pcap pcap, int cnt, H handler, T user) {
		return capture(pcap, cnt, handler, user, 0, TimeUnit.MILLISECONDS);
	}

	protected abstract int doCapture(Pcap pcap, int cnt, H handler, T user, long timeout, TimeUnit unit);
}
