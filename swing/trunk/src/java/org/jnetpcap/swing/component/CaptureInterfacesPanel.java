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
package org.jnetpcap.swing.component;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.Image;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.format.FormatUtils;

import sun.awt.image.ToolkitImage;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class CaptureInterfacesPanel
    extends
    JPanel {

	/**
	 * 
	 */
	private static final long serialVersionUID = 3504227415860832686L;

	private List<PcapIf> alldevs;

	public CaptureInterfacesPanel() {

		scanPcapInterfaces();
		createMainPanel();
	}

	/**
	 * 
	 */
	private void scanPcapInterfaces() {
		StringBuilder errbuf = new StringBuilder();
		alldevs = new ArrayList<PcapIf>();
		if (Pcap.findAllDevs(alldevs, errbuf) != Pcap.OK) {
			System.err.printf("Unable to scan system interfaces. Received error: %s",
			    errbuf);
		}

	}

	private static final int WIDTH = 600;

	private static final int COLUMN_COUNT = 5;

	private JPanel[] columns = new JPanel[COLUMN_COUNT];

	private void createMainPanel() {
		super.setLayout(new BorderLayout());

		JPanel content = new JPanel();
		super.add(content, BorderLayout.CENTER);

		content.setLayout(new BoxLayout(content, BoxLayout.X_AXIS));
		// super.setPreferredSize(new Dimension(WIDTH, 100));
		content.setBorder(BorderFactory.createEtchedBorder());
		/*
		 * Create our vertical columns
		 */
		for (int i = 0; i < COLUMN_COUNT; i++) {
			JPanel panel = columns[i] = new JPanel();
			panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

			content.add(Box.createGlue());
			content.add(panel);
		}

		createHeadings();

		for (int i = 0; i < alldevs.size(); i++) {
			createInterfacePanel(alldevs.get(i));
		}

		JPanel bottomControlPanel = new JPanel(new FlowLayout());
		final JButton closeButton = new JButton("Close");
		bottomControlPanel.add(closeButton);
		super.add(bottomControlPanel, BorderLayout.SOUTH);

		closeButton.addActionListener(new ActionListener() {

			public void actionPerformed(ActionEvent e) {
				Window win = SwingUtilities.getWindowAncestor(closeButton);
				win.setVisible(false);
			}

		});
	}

	private Icon loadIcon(String path, String description) {
		URL imgURL = getClass().getClassLoader().getResource(path);
		if (imgURL != null) {
			return new ImageIcon(imgURL, description);
		} else {
			System.err.println("Couldn't find file: " + path);
			return null;
		}
	}

	/**
	 * @param pcapIf
	 * @return
	 */
	private Component createInterfacePanel(PcapIf pcapIf) {
		JPanel panel;

		columns[0].add(panel = new JPanel());
		panel.add(new JLabel(pcapIf.getDescription(), loadIcon(
		    "resources/lan-16.png", "NIC"), JLabel.CENTER));

		String a =
		    (pcapIf.getAddresses().isEmpty()) ? "unknown" : FormatUtils.ip(pcapIf
		        .getAddresses().get(0).getAddr().getData());
		columns[1].add(panel = new JPanel());
		panel.add(new JLabel(a, JLabel.CENTER));
		JLabel p;
		columns[2].add(panel = new JPanel());
		panel.add(p = new JLabel("0", JLabel.CENTER));
		p.setForeground(Color.gray);

		JLabel ps;
		columns[3].add(panel = new JPanel());
		panel.add(ps = new JLabel("0", JLabel.CENTER));
		ps.setForeground(Color.gray);

		JPanel buttons = new JPanel();
		buttons.setLayout(new BoxLayout(buttons, BoxLayout.X_AXIS));

		buttons.add(new JButton("Start"));
		buttons.add(new JButton("Options"));
		buttons.add(new JButton("Details"));

		columns[4].add(buttons);
		return panel;
	}

	/**
	 * @return
	 */
	private JPanel createHeadings() {
		JPanel panel;

		columns[0].add(panel = new JPanel());
		panel.add(new JLabel("Description", JLabel.CENTER));

		columns[1].add(panel = new JPanel());
		panel.add(new JLabel("IP", JLabel.CENTER));

		columns[2].add(panel = new JPanel());
		panel.add(new JLabel("Packets", JLabel.CENTER));

		columns[3].add(panel = new JPanel());
		panel.add(new JLabel("Packets/s", JLabel.CENTER));

		JButton b;
		columns[4].add(panel = new JPanel(new GridLayout(1, 1)));
		panel.add(b = new JButton("Stop"));
		b.setEnabled(false);

		return panel;
	}

}
