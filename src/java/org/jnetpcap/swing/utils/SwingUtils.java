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
package org.jnetpcap.swing.utils;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Image;
import java.util.ArrayList;
import java.util.List;

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

/**
 * Various jUnit support utilities
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class SwingUtils {

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
		return displayInFrame(c, "SwingUtils");
	}

	public static JFrame displayInFrame(JComponent c, String title) {
		JFrame frame = new JFrame(title);
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
