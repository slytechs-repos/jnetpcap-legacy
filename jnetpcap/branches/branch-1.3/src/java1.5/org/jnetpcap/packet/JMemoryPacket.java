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

import java.nio.ByteBuffer;

import org.jnetpcap.JCaptureHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.format.FormatUtils;

// TODO: Auto-generated Javadoc
/**
 * The Class JMemoryPacket.
 */
public class JMemoryPacket
    extends
    JPacket {

	/**
	 * The Class JMemoryHeader.
	 */
	public static class JMemoryHeader implements JCaptureHeader {

		/** The caplen. */
		private int caplen;

		/** The in micros. */
		private long inMicros;

		/** The in millis. */
		private long inMillis;

		/** The in nanos. */
		private long inNanos;

		/** The nanos. */
		private long nanos;

		/** The seconds. */
		private long seconds;

		/** The wirelen. */
		private int wirelen;

		/**
		 * Instantiates a new j memory header.
		 */
		public JMemoryHeader() {
			this(0, 0, System.currentTimeMillis() / 1000, System.nanoTime());
			
		}

		/**
		 * Instantiates a new j memory header.
		 * 
		 * @param caplen
		 *          the caplen
		 * @param wirelen
		 *          the wirelen
		 * @param seconds
		 *          the seconds
		 * @param nanos
		 *          the nanos
		 */
		public JMemoryHeader(int caplen, int wirelen, long seconds, long nanos) {
			init(caplen, wirelen, nanos, seconds);
		}

		/* (non-Javadoc)
		 * @see org.jnetpcap.JCaptureHeader#caplen()
		 */
		public int caplen() {
			return caplen;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.JCaptureHeader#caplen(int)
		 */
		public void caplen(int caplen) {
			this.caplen = caplen;
			if (this.wirelen == 0) {
				setWirelen(caplen);
			}
		}

		/**
		 * Gets the wirelen.
		 * 
		 * @return the wirelen
		 */
		public final int getWirelen() {
			return this.wirelen;
		}

		/**
		 * Inits the.
		 * 
		 * @param caplen
		 *          the caplen
		 * @param wirelen
		 *          the wirelen
		 * @param nanos
		 *          the nanos
		 * @param seconds
		 *          the seconds
		 */
		public void init(int caplen, int wirelen, long nanos, long seconds) {
			this.caplen = caplen;
			this.wirelen = wirelen;
			this.nanos = nanos;
			this.seconds = seconds;

			initCompound();
		}

		/**
		 * Inits the compound.
		 */
		private void initCompound() {
			this.inMillis = seconds * 1000 + nanos / 1000000;
			this.inMicros = seconds * 1000000 + nanos / 1000;
			this.inNanos = seconds * 1000000000 + nanos;

		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.JCaptureHeader#initFrom(org.jnetpcap.JCaptureHeader)
		 */
		public void initFrom(JCaptureHeader header) {
			init(header.caplen(), header.wirelen(), header.nanos(), header.seconds());
		}

		/* (non-Javadoc)
		 * @see org.jnetpcap.JCaptureHeader#nanos()
		 */
		public long nanos() {
			return nanos;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.JCaptureHeader#nanos(long)
		 */
		public void nanos(long nanos) {
			this.nanos = nanos;

			initCompound();
		}

		/* (non-Javadoc)
		 * @see org.jnetpcap.JCaptureHeader#seconds()
		 */
		public long seconds() {
			return seconds;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.JCaptureHeader#seconds(long)
		 */
		public void seconds(long seconds) {
			this.seconds = seconds;

			initCompound();
		}

		/**
		 * Sets the wirelen.
		 * 
		 * @param wirelen
		 *          the new wirelen
		 */
		public final void setWirelen(int wirelen) {
			this.wirelen = wirelen;
			
			if (this.caplen == 0) {
				this.caplen = wirelen;
			}
		}

		/* (non-Javadoc)
		 * @see org.jnetpcap.JCaptureHeader#timestampInMicros()
		 */
		public long timestampInMicros() {
			return inMicros;
		}

		/* (non-Javadoc)
		 * @see org.jnetpcap.JCaptureHeader#timestampInMillis()
		 */
		public long timestampInMillis() {
			return inMillis;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.JCaptureHeader#timestampInNanos()
		 */
		public long timestampInNanos() {
			return this.inNanos;
		}

		/* (non-Javadoc)
		 * @see org.jnetpcap.JCaptureHeader#wirelen()
		 */
		public int wirelen() {
			return wirelen;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.JCaptureHeader#wirelen(int)
		 */
		public void wirelen(int wirelen) {
			this.wirelen = wirelen;
		}

	}

	/** The header. */
	private final JMemoryHeader header = new JMemoryHeader();

	/**
	 * Instantiates a new j memory packet.
	 * 
	 * @param buffer
	 *          the buffer
	 */
	public JMemoryPacket(byte[] buffer) {
		super(Type.POINTER);

		final JBuffer mem = getMemoryBuffer(buffer);
		super.peer(mem);

		header.setWirelen(buffer.length);
	}

	/**
	 * Instantiates a new j memory packet.
	 * 
	 * @param buffer
	 *          the buffer
	 * @throws PeeringException
	 *           the peering exception
	 */
	public JMemoryPacket(ByteBuffer buffer) throws PeeringException {
		super(Type.POINTER);
		
		final int size = buffer.limit() - buffer.position();

		final JBuffer mem = getMemoryBuffer(size);
		super.peer(mem);
		
		transferFrom(buffer);

		header.setWirelen(size);
	}

	/**
	 * Instantiates a new j memory packet.
	 * 
	 * @param size
	 *          the size
	 */
	public JMemoryPacket(int size) {
		super(size, 0);

		header.setWirelen(size);
		
		/**
		 * Bug #2878768	JMemoryPacket(int) constructor doesn't work
		 */
		super.peer(super.memory);
	}

	/**
	 * Instantiates a new j memory packet.
	 * 
	 * @param id
	 *          the id
	 * @param buffer
	 *          the buffer
	 */
	public JMemoryPacket(int id, byte[] buffer) {
		this(buffer);

		scan(id);
	}

	/**
	 * Instantiates a new j memory packet.
	 * 
	 * @param id
	 *          the id
	 * @param buffer
	 *          the buffer
	 * @throws PeeringException
	 *           the peering exception
	 */
	public JMemoryPacket(int id, ByteBuffer buffer) throws PeeringException {
		this(buffer);

		scan(id);
	}

	/**
	 * Instantiates a new j memory packet.
	 * 
	 * @param id
	 *          the id
	 * @param buffer
	 *          the buffer
	 */
	public JMemoryPacket(int id, JBuffer buffer) {
		this(buffer);

		scan(id);
	}

	/**
	 * Instantiates a new j memory packet.
	 * 
	 * @param id
	 *          the id
	 * @param hexdump
	 *          the hexdump
	 */
	public JMemoryPacket(int id, String hexdump) {
		this(id, FormatUtils.toByteArray(hexdump));
	}

	/**
	 * Instantiates a new j memory packet.
	 * 
	 * @param buffer
	 *          the buffer
	 */
	public JMemoryPacket(JBuffer buffer) {
		super(POINTER);

		header.setWirelen(buffer.size());

		final int len = buffer.size();
		JBuffer b = getMemoryBuffer(len);

		b.transferFrom(buffer); // Make a buffer to buffer copy

		peer(b, 0, len);
		
		header.setWirelen(len);
	}

	/**
	 * Instantiates a new j memory packet.
	 * 
	 * @param packet
	 *          the packet
	 */
	public JMemoryPacket(JMemoryPacket packet) {
		super(Type.POINTER);

		transferFrom(packet);
	}

	/**
	 * Instantiates a new j memory packet.
	 * 
	 * @param packet
	 *          the packet
	 */
	public JMemoryPacket(JPacket packet) {
		super(Type.POINTER);

		transferFrom(packet);
	}

	/**
	 * Instantiates a new j memory packet.
	 * 
	 * @param type
	 *          the type
	 */
	public JMemoryPacket(Type type) {
		super(type);
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.packet.JPacket#getCaptureHeader()
	 */
	@Override
	public JMemoryHeader getCaptureHeader() {
		return this.header;
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.packet.JPacket#getTotalSize()
	 */
	@Override
	public int getTotalSize() {
		return super.size() + super.state.size();
	}

	/**
	 * Peer state and data.
	 * 
	 * @param buffer
	 *          the buffer
	 * @return the int
	 * @throws PeeringException
	 *           the peering exception
	 */
	public int peerStateAndData(ByteBuffer buffer) throws PeeringException {
		if (buffer.isDirect() == false) {
			throw new PeeringException("unable to peer a non-direct ByteBuffer");
		}
		return peerStateAndData(getMemoryBuffer(buffer), 0);
	}

	/**
	 * Peer state and data.
	 * 
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	public int peerStateAndData(JBuffer buffer) {
		return peerStateAndData(getMemoryBuffer(buffer), 0);
	}

	/**
	 * Peer state and data.
	 * 
	 * @param buffer
	 *          the buffer
	 * @param offset
	 *          the offset
	 * @return the int
	 */
	public int peerStateAndData(JBuffer buffer, int offset) {

		state.peerTo(buffer, offset, State.sizeof(0));
		int o = state.peerTo(buffer, offset, State.sizeof(state.getHeaderCount()));
		o += super.peer(buffer, offset + o, header.caplen());

		return o;
	}

	/**
	 * Sets the wirelen.
	 * 
	 * @param wirelen
	 *          the new wirelen
	 */
	public void setWirelen(int wirelen) {
		header.setWirelen(wirelen);
	}

	/**
	 * Transfer state and data from.
	 * 
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	public int transferStateAndDataFrom(byte[] buffer) {
		JBuffer b = getMemoryBuffer(buffer);

		return peerStateAndData(b, 0);
	}

	/**
	 * Transfer state and data from.
	 * 
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	public int transferStateAndDataFrom(ByteBuffer buffer) {
		final int len = buffer.limit() - buffer.position();
		JBuffer b = getMemoryBuffer(len);

		b.transferFrom(buffer, 0);

		return peerStateAndData(b, 0);
	}

	/**
	 * Transfer state and data from.
	 * 
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	public int transferStateAndDataFrom(JBuffer buffer) {
		final int len = buffer.size();
		JBuffer b = getMemoryBuffer(len);

		b.transferFrom(buffer);

		return peerStateAndData(b, 0);
	}

	/**
	 * Transfer state and data from.
	 * 
	 * @param packet
	 *          the packet
	 * @return the int
	 */
	public int transferStateAndDataFrom(JMemoryPacket packet) {
		return packet.transferTo(this);
	}

	/**
	 * Transfer state and data from.
	 * 
	 * @param packet
	 *          the packet
	 * @return the int
	 */
	public int transferStateAndDataFrom(JPacket packet) {
		int len = packet.state.size() + packet.size();
		JBuffer mem = getMemoryBuffer(len);

		int o = packet.state.transferTo(mem, 0, packet.state.size(), 0);
		o += packet.transferTo(mem, 0, packet.size(), o);

		return o;
	}

	/**
	 * Transfer state and data to.
	 * 
	 * @param buffer
	 *          the buffer
	 * @param offset
	 *          the offset
	 * @return the int
	 */
	public int transferStateAndDataTo(JBuffer buffer, int offset) {
		int o = state.transferTo(buffer, 0, state.size(), offset);
		o += super.transferTo(buffer, 0, size(), offset + o);

		return o;
	}

	/**
	 * Transfer state and data to.
	 * 
	 * @param packet
	 *          the packet
	 * @return the int
	 */
	public int transferStateAndDataTo(JMemoryPacket packet) {
		final JBuffer buffer = packet.getMemoryBuffer(this.getTotalSize());

		packet.transferStateAndDataTo(buffer, 0);

		return peerStateAndData(buffer, 0);
	}
}
