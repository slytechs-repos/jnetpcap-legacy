package org.jnetpcap.util.resolver;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.jnetpcap.util.JLogger;

/**
 * A resolver object that knows how to convert IP addresses into hostnames.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class IpResolver
    extends AbstractResolver {

	/**
	 * @param type
	 */
	public IpResolver() {
		super(JLogger.getLogger(IpResolver.class), "IP");
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFormatter.AbstractResolver#resolveToName(byte[],
	 *      int)
	 */
	@Override
	public String resolveToName(byte[] address, long hash) {
		try {
			InetAddress i = InetAddress.getByAddress(address);
			String host = i.getHostName();
			if (Character.isDigit(host.charAt(0)) == false) {
				return host;
			}

		} catch (UnknownHostException e) {
			e.printStackTrace();
		}
		return null;

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFormatter.AbstractResolver#toHashCode(byte[])
	 */
	@Override
	public long toHashCode(byte[] address) {
		long hash =
		    ((address[3] < 0) ? address[3] + 256 : address[3])
		        | ((address[2] < 0) ? address[2] + 256 : address[2]) << 8
		        | ((address[1] < 0) ? address[1] + 256 : address[1]) << 16
		        | ((address[0] < 0) ? address[0] + 256 : address[0]) << 24;

		return hash;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.util.AbstractResolver#resolveToName(long, long)
	 */
	@Override
	protected String resolveToName(long number, long hash) {
		throw new UnsupportedOperationException(
		    "this resolver only resolves addresses in byte[] form");
	}

}