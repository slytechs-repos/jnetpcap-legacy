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

import java.awt.Dimension;
import java.util.HashMap;
import java.util.Map;

import javax.swing.BoxLayout;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.packet.analysis.AnalyzerListener;
import org.jnetpcap.packet.analysis.JController;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.TcpAnalyzer;
import org.jnetpcap.protocol.tcpip.TcpStreamEvent;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TcpStreamMonitorApp
    extends JFrame implements AnalyzerListener<TcpStreamEvent>, Runnable {

	private final Map<Integer, TcpStreamPanel> streams =
	    new HashMap<Integer, TcpStreamPanel>();

	/**
	 * 
	 */
	private static final long serialVersionUID = 2218471248660810552L;

	private JTabbedPane main;

	private JScrollPane scrollPane;

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		TcpStreamMonitorApp frame = new TcpStreamMonitorApp();

		frame.setVisible(true);

		frame.setupTimer();

		frame.openCapture(TestUtils.HTTP);

	}

	/**
	 * 
	 */
	private void setupTimer() {
		SwingUtilities.invokeLater(this);

		// Timer timer = new Timer(10, new ActionListener() {
		//
		// public void actionPerformed(ActionEvent e) {
		// process();
		// }
		//
		// });
		//
		// timer.start();
	}

	public void run() {
		synchronized (streams) {
			for (TcpStreamPanel stream : streams.values()) {
				stream.process();
			}
		}

		SwingUtilities.invokeLater(this);
	}

	/**
	 * @param file
	 */

	private void openCapture(String file) {
		TcpAnalyzer tcpAnalyzer = JRegistry.getAnalyzer(TcpAnalyzer.class);
		tcpAnalyzer.addTcpStreamListener(this, null);

//		TestUtils.openOffline(file, JRegistry.getAnalyzer(JController.class));
		TestUtils.openLive(100, JRegistry.getAnalyzer(JController.class));
	}

	public TcpStreamMonitorApp() {
		super("Tcp Stream Monitor");
		super.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

		main = new JTabbedPane();
		main.setPreferredSize(new Dimension(600, 400));
		this.getContentPane().add(main);
		this.pack();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.analysis.AnalyzerListener#processAnalyzerEvent(org.jnetpcap.packet.analysis.AnalyzerEvent)
	 */
	public void processAnalyzerEvent(TcpStreamEvent evt) {
		int hash = evt.hashCode();
		final JPacket packet = evt.getPacket();

		TcpStreamPanel stream = streams.get(hash);
		if (stream == null) {
			stream = new TcpStreamPanel(hash, evt.getDuplex(), main.getTabCount());
			synchronized (streams) {
				streams.put(hash, stream);
			}
			addStream(stream, evt.getDuplex().toString());

			System.out.printf("\n%08X %s:: ", hash, evt.getDuplex().toString());
		}

		if (evt.getType() == TcpStreamEvent.Type.ACK_FOR_UNSEEN_SEGMENT
		    || evt.getType() == TcpStreamEvent.Type.OUT_OF_ORDER_SEGMENT) {
			main.setTitleAt(stream.getId(), evt.getDuplex().toString() + "(!)");
		}

		stream.offer(evt);
		
		stream.revalidate();
		stream.repaint();

		System.out.flush();
	}

	private void addStream(TcpStreamPanel stream, String name) {
		main.addTab(name, stream.getScroll());
	}

}
