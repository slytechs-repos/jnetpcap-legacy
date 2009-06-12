/**
 * Copyright (C) 2008 Sly Technologies, Inc. This library is free software; you
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
package org.jnetpcap.packet;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Image;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.DefaultListModel;
import javax.swing.DefaultListSelectionModel;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;
import javax.swing.border.BevelBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import junit.framework.TestCase;

import org.jnetpcap.JBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.PcapTask;
import org.jnetpcap.PcapUtils;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.protocol.JProtocol;

/**
 * Various jUnit support utilities
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestUtils
    extends
    TestCase {

	public final static String AFS = "tests/test-afs.pcap";

	public final static String HTTP = "tests/test-http-jpeg.pcap";

	public final static String VLAN = "tests/test-vlan.pcap";

	public final static String REASEMBLY = "tests/test-ipreassembly.pcap";

	public final static String IP6 = "tests/test-ipv6.pcap";

	public final static String L2TP = "tests/test-l2tp.pcap";

	public final static String MYSQL = "tests/test-mysql.pcap";

	/**
	 * Special Appendable device that throws away its output. Used in stress
	 * testing formatters where actual output is not required.
	 */
	public final static Appendable DEV_NULL = new Appendable() {

		public Appendable append(CharSequence csq) throws IOException {
			return this;
		}

		public Appendable append(char c) throws IOException {
			return this;
		}

		public Appendable append(CharSequence csq, int start, int end)
		    throws IOException {
			return this;
		}

	};

	private static JScanner scanner = new JScanner();

	/**
	 * Scans a packet that has been initialized but not scanned. Assumes ethernet
	 * is the DLT protocol
	 * 
	 * @param packet
	 *          packet to scan
	 * @return offset into the packet
	 */
	public static int scanPacket(JPacket packet) {
		return scanPacket(packet, JProtocol.ETHERNET_ID);
	}

	/**
	 * Scans a packet that has been initialized but not scanned.
	 * 
	 * @param packet
	 *          packet to scan
	 * @param id
	 *          id of the DLT protocol
	 * @return offset into the packet
	 */
	public static int scanPacket(JPacket packet, int id) {

		return scanner.scan(packet, id);
	}

	public static Iterable<PcapPacket> getIterable(final String file) {
		return new Iterable<PcapPacket>() {

			public Iterator<PcapPacket> iterator() {
				return getPcapPacketIterator(file, 0, Integer.MAX_VALUE);
			}

		};
	}

	/**
	 * Creates a packet iterator that iterates over packets within specified index
	 * range. If Integer.MAX_VALUE is used for end, means to the end of file.
	 * 
	 * @param file
	 *          pcap file to open
	 * @param start
	 *          starting packet index within the file
	 * @param end
	 *          end index or if Integer.MAX_VALUE to the end of the file
	 * @return iterator with packets
	 */
	public static Iterator<PcapPacket> getPcapPacketIterator(
	    final String file,
	    final int start,
	    final int end) {

		/***************************************************************************
		 * First, open offline file
		 **************************************************************************/
		StringBuilder errbuf = new StringBuilder();

		final Pcap pcap = Pcap.openOffline(file, errbuf);
		if (pcap == null) {
			System.err.println(errbuf.toString());
			return null;
		}

		final BlockingQueue<PcapPacket> queue =
		    new ArrayBlockingQueue<PcapPacket>(100);

		/***************************************************************************
		 * Third, Enter our loop and count packets until we reach the index of the
		 * packet we are looking for.
		 **************************************************************************/

		final PcapTask<Pcap> task =
		    PcapUtils.loopInBackground(pcap, end, new JBufferHandler<Pcap>() {
			    int i = 0;

			    public void nextPacket(PcapHeader header, JBuffer buffer, Pcap pcap) {

				    if (i >= start) {
					    PcapPacket packet = new PcapPacket(header, buffer);
					    // packet.scan(JRegistry.mapDLTToId(pcap.datalink()));
					    /*
							 * Put the packet on the queue. No scan, scan is delayed for
							 * maximum performance in this thread.
							 */
					    queue.offer(packet);
				    }

				    i++;
			    }

		    }, pcap);
		try {
			task.start();
		} catch (InterruptedException e1) {
			throw new IllegalStateException(e1);
		}

		return new Iterator<PcapPacket>() {
			private Pcap p = pcap;

			private int id = JRegistry.mapDLTToId(pcap.datalink());

			public boolean hasNext() {
				if (p != null && task.isAlive() == false) {
					p.close();
					p = null;
				}
				return queue.isEmpty() == false || p != null;
			}

			public PcapPacket next() {
				try {
					/*
					 * We take the packet from the queue and scan it. We scan here not in
					 * the dispatcher loop, because we want the dispatcher thread to be as
					 * fast as possible. We have a queue, so packets can queue up on it,
					 * while in the user thread we scan the packets, possibly creating a
					 * backlog on the queue.
					 */
					PcapPacket packet = queue.take();
					packet.scan(id);
					return packet;
				} catch (InterruptedException e) {
					throw new IllegalStateException(e);
				}
			}

			public void remove() {
				throw new UnsupportedOperationException(
				    "Invalid operation for readonly offline read");
			}

		};
	}

	/**
	 * Retrieves a specific single packet from a file
	 * 
	 * @param file
	 *          capture file containing our packet
	 * @param index
	 *          0 based index of the packet to get
	 * @return the requested packet
	 */
	public static PcapPacket getPcapPacket(final String file, final int index) {

		/***************************************************************************
		 * First, open offline file
		 **************************************************************************/
		StringBuilder errbuf = new StringBuilder();

		final Pcap pcap = Pcap.openOffline(file, errbuf);
		if (pcap == null) {
			System.err.println(errbuf.toString());
			return null;
		}

		/***************************************************************************
		 * Second, setup a packet we're going to copy the captured contents into.
		 * Allocate 2K native memory block to hold both state and buffer. Notice
		 * that the packet has to be marked "final" in order for the JPacketHandler
		 * to be able to access that variable from within the loop.
		 **************************************************************************/
		final PcapPacket result = new PcapPacket(2 * 1024);

		/***************************************************************************
		 * Third, Enter our loop and count packets until we reach the index of the
		 * packet we are looking for.
		 **************************************************************************/
		try {
			pcap.loop(Pcap.LOOP_INFINATE, new JBufferHandler<Pcap>() {
				int i = 0;

				public void nextPacket(PcapHeader header, JBuffer buffer, Pcap pcap) {

					/*********************************************************************
					 * Forth, once we reach our packet transfer the capture data from our
					 * temporary, shared packet, to our preallocated permanent packet. The
					 * method transferStateAndDataTo will do a deep copy of the packet
					 * contents and state to the destination packet. The copy is done
					 * natively with memcpy. The packet content in destination packet is
					 * layout in memory as follows. At the front of the buffer is the
					 * packet_state_t structure followed immediately by the packet data
					 * buffer and its size is adjusted to the exact size of the temporary
					 * buffer. The remainder of the allocated memory block is unused, but
					 * needed to be allocated large enough to hold a decent size packet.
					 * To break out of the Pcap.loop we call Pcap.breakLoop().
					 ********************************************************************/
					if (i++ == index) {
						PcapPacket packet = new PcapPacket(header, buffer);
						packet.scan(JRegistry.mapDLTToId(pcap.datalink()));

						packet.transferStateAndDataTo(result);

						pcap.breakloop();
						return;
					}
				}

			}, pcap);
		} finally {

			/*************************************************************************
			 * Lastly, we close the pcap handle and return our result :)
			 ************************************************************************/
			pcap.close();
		}

		return result;
	}

	/**
	 * Opens up a pcap handle to specific file
	 * 
	 * @param fname
	 */
	public static Pcap openOffline(String fname) {
		/***************************************************************************
		 * First, open offline file
		 **************************************************************************/
		StringBuilder errbuf = new StringBuilder();

		final Pcap pcap = Pcap.openOffline(fname, errbuf);
		if (pcap == null) {
			System.err.println(errbuf.toString());
			return null;
		}

		return pcap;
	}

	/**
	 * @param file
	 * @param start
	 * @param end
	 * @return
	 */
	public static Iterable<JPacket> getJPacketIterable(
	    final String file,
	    final int start,
	    final int end) {

		return new Iterable<JPacket>() {

			public Iterator<JPacket> iterator() {
				final Iterator<PcapPacket> i = getPcapPacketIterator(file, start, end);
				return new Iterator<JPacket>() {

					public boolean hasNext() {
						return i.hasNext();
					}

					public JPacket next() {
						return i.next();
					}

					public void remove() {
						i.remove();
					}

				};
			}

		};
	}

	public static void openOffline(String file, JPacketHandler<Pcap> handler) {
		openOffline(file, handler, null);
	}

	public static void openOffline(
	    String file,
	    JPacketHandler<Pcap> handler,
	    String filter) {
		StringBuilder errbuf = new StringBuilder();

		Pcap pcap;

		if ((pcap = Pcap.openOffline(file, errbuf)) == null) {
			fail(errbuf.toString());
		}

		if (filter != null) {
			PcapBpfProgram program = new PcapBpfProgram();
			if (pcap.compile(program, filter, 0, 0) != Pcap.OK) {
				System.err.printf("pcap filter err: %s\n", pcap.getErr());
			}

			pcap.setFilter(program);
		}

		pcap.loop(Pcap.LOOP_INFINATE, handler, pcap);

		pcap.close();
	}

	public static void openLive(JPacketHandler<Pcap> handler) {
		openLive(Pcap.LOOP_INFINATE, handler);
	}

	/**
	 * 
	 */
	public static void openLive(long count, JPacketHandler<Pcap> handler) {
		StringBuilder errbuf = new StringBuilder();
		List<PcapIf> alldevs = new ArrayList<PcapIf>();

		if (Pcap.findAllDevs(alldevs, errbuf) != Pcap.OK) {
			throw new IllegalStateException(errbuf.toString());
		}

		Pcap pcap =
		    Pcap.openLive(alldevs.get(0).getName(), Pcap.DEFAULT_SNAPLEN,
		        Pcap.DEFAULT_PROMISC, Pcap.DEFAULT_TIMEOUT, errbuf);
		if (pcap == null) {
			throw new IllegalArgumentException(errbuf.toString());
		}

		pcap.loop((int) count, handler, pcap);
	}

	public static class JImagePanel
	    extends
	    JPanel {
		private Image img;

		public final Image getImg() {
			return this.img;
		}

		public final void setImg(Image img) {
			this.img = resizeToComponentSize(img);
		}

		public Image resizeToComponentSize(Image img) {

			int cw = super.getWidth();
			int ch = super.getHeight();
			int iw = img.getWidth(this);
			int ih = img.getHeight(this);
			if (iw == -1 || ih == -1) {
				return img;
			}

			/*
			 * Rescale by width
			 */
			if ((iw > ih) && iw > cw) {
				img = img.getScaledInstance(cw, -1, Image.SCALE_FAST);
			} else if (ih > ch) {
				img = img.getScaledInstance(-1, ch, Image.SCALE_FAST);
			}

			return img;
		}

		/**
		 * @param img
		 */
		public JImagePanel() {
			super.setSize(new Dimension(100, 100));
		}

		/**
		 * @param img
		 */
		public JImagePanel(Image img) {
			this.img = img;
		}

		@Override
		public void paint(Graphics g) {
			super.paint(g);

			if (this.img == null || this.img.getWidth(this) == -1) {
				return;
			}

			Image img = this.img;

			if (img == null) {
				return;
			}

			int w = getWidth();
			int h = getHeight();

			int x = w / 2 - img.getWidth(this) / 2;
			int y = h / 2 - img.getHeight(this) / 2;

			g.drawImage(img, x, y, this);
			g.drawString("(w=" + img.getWidth(this) + ", h=" + img.getHeight(this)
			    + ")", 20, 20);
		}

	}

	public static class ListOfPanels
	    extends
	    JPanel implements ListSelectionListener {
		private static class Entry {
			Image img;

			String text;

			public Entry(Image img, String text) {
				this.img = img;
				this.text = text;
			}

			public String toString() {
				return text;
			}

			public final Image getImg() {
				return this.img;
			}

			public final void setImg(Image img) {
				this.img = img;
			}

			public final String getText() {
				return this.text;
			}

			public final void setText(String text) {
				this.text = text;
			}
		}

		private final List<Entry> list = new ArrayList<Entry>(50);

		private JPanel listPanel = new JPanel();

		private JImagePanel imagePanel = new JImagePanel();

		private JList jlist;

		private DefaultListModel listModel;

		public void init() {
			super.setPreferredSize(new Dimension(500, 800));
			super.setLayout(new BorderLayout());

			super.add(listPanel, BorderLayout.NORTH);

			super.add(imagePanel, BorderLayout.CENTER);

			listModel = new DefaultListModel();
			jlist = new JList(listModel);
			jlist.addListSelectionListener(this);
			jlist.setSelectionMode(DefaultListSelectionModel.SINGLE_SELECTION);
			jlist.setLayoutOrientation(JList.VERTICAL_WRAP);

			JScrollPane listScroller = new JScrollPane(jlist);
			listScroller.setPreferredSize(new Dimension(250, 400));
			listScroller.setAlignmentX(LEFT_ALIGNMENT);

			// Create a container so that we can add a title around
			// the scroll pane. Can't add a title directly to the
			// scroll pane because its background would be white.
			// Lay out the label and scroll pane from top to bottom.
			listPanel.setLayout(new BoxLayout(listPanel, BoxLayout.PAGE_AXIS));
			JLabel label = new JLabel("Captured Images");
			label.setLabelFor(jlist);
			listPanel.add(label);
			listPanel.add(Box.createRigidArea(new Dimension(0, 5)));
			listPanel.add(listScroller);
			listPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

			jlist.setBorder(BorderFactory.createBevelBorder(BevelBorder.LOWERED));
			listPanel.setBorder(BorderFactory.createBevelBorder(BevelBorder.RAISED));
			listPanel.setPreferredSize(new Dimension(100, 200));

			if (list.isEmpty() == false) {
				imagePanel.setImg(list.get(list.size() - 1).getImg());
			}
		}

		public void add(Image img, String text) {
			final Entry e = new Entry(img, text);
			list.add(e);

			if (jlist != null) {
				SwingUtilities.invokeLater(new Runnable() {
					public void run() {
						listModel.addElement(e);
						jlist.setSelectedIndex(list.size() - 1);
					}
				});
			}
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see javax.swing.event.ListSelectionListener#valueChanged(javax.swing.event.ListSelectionEvent)
		 */
		public void valueChanged(ListSelectionEvent e) {
			// if (e.getValueIsAdjusting()) {
			// return;
			// }

			int first = ((JList) e.getSource()).getSelectedIndex();
			Image img = list.get(first).getImg();

			// Image img = ((JList) e.getSource()).getSelectedIndex();

			imagePanel.setImg(img);
			imagePanel.repaint();
		}

		/**
		 * @return
		 */
		public boolean isEmpty() {
			return this.list.isEmpty();
		}

	}

	public static JFrame displayInFrame(JComponent c) {
		JFrame frame = new JFrame("TestUtils");
		frame.getContentPane().add(c);
		frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE
		    | JFrame.EXIT_ON_CLOSE);

		frame.setSize(new Dimension(400, 800));
		frame.setAlwaysOnTop(true);

		frame.pack();

		frame.setVisible(true);

		return frame;
	}
}
