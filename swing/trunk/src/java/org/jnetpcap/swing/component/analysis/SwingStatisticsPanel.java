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
package org.jnetpcap.swing.component.analysis;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Formatter;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.SwingUtilities;

import org.jnetpcap.packet.analysis.StatisticAnalyzer;
import org.jnetpcap.protocol.JProtocol;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class SwingStatisticsPanel
    extends
    JPanel {

	/**
	 * 
	 */
	private static final long serialVersionUID = 425023294447164009L;

	/**
	 * 
	 */
	private static final int WIDTH = 400;

	private int COUNT = JProtocol.values().length;

	private final StatisticAnalyzer stats;

	private JPanel statsPanel;

	private JPanel statusPanel;

	JComponent[][] table = new JComponent[COUNT][4];

	private Thread thread;

	private JLabel totalCountLabel;

	private JLabel timeLabel;

	private JButton stopButton;

	private ActionListener defaultAction;

	/**
	 * @param stats
	 */
	public SwingStatisticsPanel(StatisticAnalyzer stats) {
		this.stats = stats;

		createMainPanel();

		start();
	}

	private void createMainPanel() {

		super.setLayout(new BorderLayout());

		add(createStatsPanel(), BorderLayout.CENTER);

		add(createStatusPanel(), BorderLayout.SOUTH);
	}

	private JPanel createStatsPanel() {
		JPanel panel = new JPanel();
		panel.setLayout(new GridLayout(COUNT + 1, 4));

		panel.setPreferredSize(new Dimension(WIDTH, 400));

		panel.setBorder(BorderFactory.createTitledBorder(BorderFactory
		    .createEtchedBorder(), "Captured Packets"));

		panel.add(new JLabel("Total"));
		panel.add(totalCountLabel = new JLabel("0", JLabel.CENTER));
		panel.add(new JLabel("% of total"));
		panel.add(new JLabel());

		String[] labels = StatisticAnalyzer.allLabels();

		for (int i = 0; i < COUNT; i++) {
			table[i][0] = new JLabel(labels[i]);
			table[i][1] = new JLabel("0", JLabel.CENTER);
			table[i][2] = new JProgressBar(0, 100);
			table[i][3] = new JLabel("0.0%", JLabel.RIGHT);
			
			panel.add(table[i][0]);
			panel.add(table[i][1]);
			panel.add(table[i][2]);
			panel.add(table[i][3]);
		}

		return panel;

	}

	private JPanel createStatusPanel() {
		JPanel panel = new JPanel();
		panel.setPreferredSize(new Dimension(WIDTH, 60));
		panel.setLayout(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

		JLabel runningLabel = new JLabel("Running", JLabel.CENTER);
		timeLabel = new JLabel("00:00:00", JLabel.CENTER);
		stopButton = new JButton("Stop");
		stopButton.setMaximumSize(new Dimension(30, 20));

		panel.add(runningLabel, BorderLayout.WEST);
		panel.add(timeLabel, BorderLayout.CENTER);
		panel.add(stopButton, BorderLayout.SOUTH);
		
		stopButton.addActionListener(defaultAction = new ActionListener() {

			public void actionPerformed(ActionEvent e) {
				
				stop();
				
				Window win = SwingUtilities.getWindowAncestor(SwingStatisticsPanel.this);
				win.setVisible(false);
      }
			
		});

		return panel;
	}
	
	public void addStopActionListener(ActionListener action) {
		this.stopButton.removeActionListener(defaultAction);
		this.stopButton.addActionListener(action);
	}
	
	public void removeStopActionListener(ActionListener action) {
		this.stopButton.removeActionListener(action);
	}

	private void start() {
		thread = new Thread(new Runnable() {

			/*
			 * Main task. Executed in background thread.
			 */
			public void run() {
				
				long startTime = System.currentTimeMillis();
				StringBuilder buf;
				Formatter formatter = new Formatter(buf = new StringBuilder());
				while (thread != null) {
					// Sleep for up to one second.
					try {
						Thread.sleep(1000);
						
						int seconds = (int) (System.currentTimeMillis() - startTime) / 1000;
						int minutes = seconds / 60 % 24;
						int hours = seconds / 3600;
						seconds %= 60;
						
						
						buf.setLength(0);
						formatter.format("%02d:%02d:%02d", hours, minutes, seconds);
						timeLabel.setText(formatter.toString());

						long[] snapshot = stats.snapshot();
						long total = stats.total();
						
						totalCountLabel.setText(Long.toString(total));

						for (int i = 0; i < COUNT; i++) {
							int c = (int) snapshot[i];
							int p = (total == 0) ? 0 : (int) (c * 100 / total);
							
							/*
							 * Update packet counter for each protocol
							 */
							JLabel label = (JLabel) table[i][1];
							label.setText(Integer.toString(c));
							
							/*
							 * Update progress bar for each protocol
							 */
							JProgressBar bar = (JProgressBar) table[i][2];
							bar.setValue(p);
							
							/*
							 * Update packet counter for each protocol
							 */
							label = (JLabel) table[i][3];
							label.setText(Float.toString((float) p) + "%");

						}

					} catch (InterruptedException ignore) {
					}
				}
			}
		});

		thread.start();
	}
	
	public void stop() {
		thread = null;
	}
}
