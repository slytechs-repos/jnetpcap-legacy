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
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Formatter;

import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JRadioButton;
import javax.swing.SwingUtilities;

import org.jnetpcap.packet.analysis.StatisticAnalyzer;
import org.jnetpcap.packet.analysis.Statistics;

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

	private final int COUNT;

	private final Statistics stats;

	private final JComponent[][] table;

	private Thread thread;

	private JLabel totalCountLabel;

	private JLabel timeLabel;

	private JButton stopButton;

	private ActionListener defaultAction;

	/**
	 * @param stats
	 */
	public SwingStatisticsPanel(Statistics stats) {
		this.stats = stats;

		this.COUNT = stats.size();

		this.table = new JComponent[COUNT][4];

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

		/*
		 * Give each row atleast 20 px in height
		 */
		panel.setPreferredSize(new Dimension(WIDTH, 50 + COUNT * 20));

		panel.setBorder(BorderFactory.createTitledBorder(BorderFactory
		    .createEtchedBorder(), "Captured Packets"));

		panel.add(new JLabel("Total"));
		panel.add(totalCountLabel = new JLabel("0", JLabel.CENTER));
		panel.add(new JLabel("% of total"));
		panel.add(new JLabel()); // Needed as a place holder

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
		panel.setPreferredSize(new Dimension(WIDTH, 100));
		panel.setLayout(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

		JLabel runningLabel = new JLabel("Running", JLabel.CENTER);
		timeLabel = new JLabel("00:00:00", JLabel.CENTER);
		stopButton = new JButton("Stop");
		stopButton.setMaximumSize(new Dimension(30, 20));

		panel.add(runningLabel, BorderLayout.WEST);
		panel.add(timeLabel, BorderLayout.CENTER);
		panel.add(stopButton, BorderLayout.SOUTH);

		JPanel optionPanel = new JPanel(new GridLayout(2, 1));
		optionPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory
		    .createEtchedBorder(), "Time display"));
		JRadioButton relativeCheckbox = new JRadioButton("relative");
		JRadioButton absoluteCheckbox = new JRadioButton("absolute");

		if (timeMode == TimeMode.RELATIVE) {
			relativeCheckbox.setSelected(true);
		} else {
			absoluteCheckbox.setSelected(true);
		}

		ButtonGroup group = new ButtonGroup();
		group.add(relativeCheckbox);
		group.add(absoluteCheckbox);

		optionPanel.add(relativeCheckbox);
		optionPanel.add(absoluteCheckbox);

		panel.add(optionPanel, BorderLayout.EAST);

		stopButton.addActionListener(defaultAction = new ActionListener() {

			public void actionPerformed(ActionEvent e) {

				stop();

				Window win =
				    SwingUtilities.getWindowAncestor(SwingStatisticsPanel.this);
				win.setVisible(false);
			}

		});
		
		absoluteCheckbox.addActionListener(new ActionListener() {

			public void actionPerformed(ActionEvent e) {
				timeMode = TimeMode.ABSOLUTE;
				updateTimeLabel();
     }
			
		});
		
		relativeCheckbox.addActionListener(new ActionListener() {

			public void actionPerformed(ActionEvent e) {
				timeMode = TimeMode.RELATIVE;
				updateTimeLabel();
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

				startTime = System.currentTimeMillis(); // Reset start time to current
				while (thread != null) {
					// Sleep for one second.
					try {
						Thread.sleep(1000);

						updateTimeLabel();

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
							 * Update packet capture percentage for each protocol
							 */
							label = (JLabel) table[i][3];
							label.setText(Float.toString((float) p) + "%");

						}

					} catch (InterruptedException ignore) {
					}
				}
			}
		});

		thread.setDaemon(true);
		thread.start();
	}

	public enum TimeMode {
		RELATIVE,
		ABSOLUTE,
	}

	private StringBuilder buf = new StringBuilder();

	private Formatter formatter = new Formatter(buf);

	private long startTime = System.currentTimeMillis();

	private TimeMode timeMode = TimeMode.RELATIVE;

	private SimpleDateFormat absoluteDate =  new SimpleDateFormat("HH:mm:ss");

	public void updateTimeLabel() {

		if (timeMode == TimeMode.RELATIVE) {

			int delta = (int) (System.currentTimeMillis() - startTime) / 1000;
			int minutes = delta / 60 % 24;
			int hours = delta / 3600;
			int seconds = delta % 60;

			buf.setLength(0);
			formatter.format("%02d:%02d:%02d", hours, minutes, seconds);
			timeLabel.setText(formatter.toString());
		} else {
			String s = absoluteDate.format(new Date());
			timeLabel.setText(s);
		}

	}

	public void stop() {
		thread = null;
	}
}
