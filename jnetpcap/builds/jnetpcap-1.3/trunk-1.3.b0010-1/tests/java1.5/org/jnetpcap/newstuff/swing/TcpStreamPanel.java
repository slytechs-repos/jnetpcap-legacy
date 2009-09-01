/**
 * Copyright (C) 2009 Sly Technologies, Inc. This library is free software; you
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
package org.jnetpcap.newstuff.swing;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Graphics;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JScrollPane;

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.TcpDuplexStream;
import org.jnetpcap.protocol.tcpip.TcpStreamEvent;
import org.jnetpcap.protocol.tcpip.TcpDuplexStream.Direction;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TcpStreamPanel
    extends JComponent {

	private static class Entry {
		public Color color;

		public TcpStreamEvent evt;

		public JPacket packet;

		public Tcp tcp;

		public String message;
	}

	private static final int BOX_HEIGHT = 60;

	private static final int BOX_WIDTH = 120;

	private static final int QUEUE_SIZE = 1000;

	/**
	 * 
	 */
	private static final long serialVersionUID = -2722946031157732144L;

	private static final int SPACE = 4;

	private static final int X_MARGIN = 10;

	private static final int Y_MARGIN = 30;

	private List<Entry> boxes = new ArrayList<Entry>(QUEUE_SIZE);

	private BlockingQueue<TcpStreamEvent> events =
	    new ArrayBlockingQueue<TcpStreamEvent>(QUEUE_SIZE);

	private final int hash;

	private int height;

	private int last = 0;

	private int max_x;

	private int max_y;

	private JScrollPane scroll;

	private int width;

	private final int id;

	public TcpStreamPanel(int hash, TcpDuplexStream duplex, int id) {
		this.hash = hash;
		this.id = id;

		super.setBorder(BorderFactory.createLineBorder(Color.black));
		super.setPreferredSize(new Dimension(100, 800));

		scroll =
		    new JScrollPane(this, JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
		        JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		scroll.setMinimumSize(new Dimension(100, 100));
	}

	private void drawBox(Graphics g, int i, Entry entry) {
		int row = i / max_x;
		i %= max_x;
		int x = X_MARGIN + i * BOX_WIDTH + i * SPACE;
		int y = Y_MARGIN + row * BOX_HEIGHT * 2;
		int width = BOX_WIDTH;
		int height = BOX_HEIGHT;
		
		if (y > getHeight()) {
			super.setPreferredSize(new Dimension(getWidth(), y + Y_MARGIN * 3));
			revalidate();
		}

		// System.out.printf(
		// "update(%x,%d) i=%d, x=%d, y=%d, w=%d, h=%d, row=%d max_x=%d\n", hash,
		// boxes.size(), i, x, y, width, height, row, max_x);

		g.setColor(entry.color);
		g.fillRect(x, y, width, height);
		g.setColor(Color.BLACK);
		g.drawRect(x, y, width, height);

		long seq = entry.evt.getDuplex().getNormalizedSequence(entry.tcp);
		long ack = entry.evt.getDuplex().getNormalizedAck(entry.tcp);
		int len = entry.tcp.getPayloadLength();
		long num = entry.evt.getPacket().getFrameNumber();
		String flags = "[" + entry.tcp.flagsCompactString() + "]";
		// String flags = entry.tcp.flagsEnum().toString();

		int d = BOX_HEIGHT / 5;

		if (entry.color == Color.blue) {
			g.setColor(Color.white);
		} else {
			g.setColor(Color.black);
		}
		g.drawString("s: " + Long.toString(seq) + "-" + Long.toString(seq + len), x
		    + BOX_WIDTH / 10, y + d);
		g.drawString("a: " + Long.toString(ack), x + BOX_WIDTH / 10, y + d * 2);
		g.drawString("l: " + Integer.toString(len), x + BOX_WIDTH / 10, y + d * 3);

		if (entry.message != null) {
			g.drawString(entry.message, x + BOX_WIDTH / 10, y + d * 4);
		}
		
		g.setColor(Color.black);
		g.drawString("TCP #" + Long.toString(num) + " " + flags,
		    x + BOX_WIDTH / 10, y + d * 0);

	}

	public final JScrollPane getScroll() {
		return this.scroll;
	}

	/**
	 * @param evt
	 */
	public void offer(TcpStreamEvent evt) {
		events.offer(evt);
	}

	@Override
	public void paintComponent(Graphics g) {
		super.paintComponent(g);

		updateGeometry();

		final int size = boxes.size();
		for (int i = size; i > last; i--) {
			drawBox(g, i-1, boxes.get(i-1));
		}

		last = size;
	}

	public void process() {
		while (events.isEmpty() == false) {

			try {
				TcpStreamEvent evt = events.take();
				process(evt);

			} catch (InterruptedException e) {
				e.printStackTrace();
			} finally {
				// System.out.printf("done\n");
			}
		}
	}

	public void process(TcpStreamEvent evt) {

		Entry entry = new Entry();
		entry.evt = evt;
		entry.tcp = entry.evt.getPacket().getHeader(new Tcp());
		Direction dir = evt.getDuplex().getDirection(entry.tcp);
		entry.message = evt.getType().toString();

		System.out.printf("#%d ", evt.getPacket().getFrameNumber(), entry.tcp
		    .toString());

		// System.out.printf("EVT(%x)=%s\n", evt.uniDirectionalHashCode(),
		// evt.getType());

		switch (evt.getType()) {
			// case ACK:
			case ACKED_SEGMENT:
				entry.color = (dir == Direction.CLIENT) ? Color.blue : Color.green;
				break;

			case OUT_OF_ORDER_SEGMENT:
				entry.color = Color.lightGray;
				entry.message = "OUT OF ORDER";
				break;

			case ACK_FOR_UNSEEN_SEGMENT:
				entry.color = Color.red;
				entry.message = "UNSEEN";
				break;

			case SYN_COMPLETE:
			case SYN_START:
			case FIN_COMPLETE:
			case FIN_START:
				entry.color = Color.yellow;
				break;
			default:
				System.out.printf("(~%s#%d)", evt.getType(), evt.getPacket()
				    .getFrameNumber());
				return;
		}

		boxes.add(entry);
	}

	private void updateGeometry() {
		width = getWidth() - X_MARGIN * 2;
		height = getHeight() - Y_MARGIN * 2;
		max_x = width / (BOX_WIDTH + SPACE);
		max_x -=
		    max_x / (BOX_WIDTH + SPACE)
		        + ((max_x % (BOX_WIDTH + SPACE) != 0) ? 0 : 0);
		max_y = height / BOX_HEIGHT;
		last = 0;
	}

	public final int getId() {
		return this.id;
	}

}
