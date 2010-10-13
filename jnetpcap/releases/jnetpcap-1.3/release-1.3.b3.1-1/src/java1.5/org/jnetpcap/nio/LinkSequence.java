/**
 * 
 */
package org.jnetpcap.nio;


/**
 * @author markbe
 * 
 */
public class LinkSequence<T> {

	private Link<T> first;
	private Link<T> last;

	private int size;

	public void add(Link<T> l) {
		if (l.linkNext() != null || l.linkPrev() != null) {
			throw new IllegalStateException("link element already part of list");
		}

		if (last == null) {
			first = l;
			last = l;
		} else {
			last.linkNext(l);
			l.linkPrev(last);
			last = l;
		}

		size++;
	}

	public boolean isEmpty() {
		return size == 0;
	}

	public void remove(Link<T> l) {
		final Link<T> p = l.linkPrev();
		final Link<T> n = l.linkNext();

		if (p == null && n == null) { // Only element in the list
			first = null;
			last = null;

		} else if (p == null) { // The first of many elements on the list
			first = n;
			first.linkPrev(null);

		} else if (n == null) { // The last of many elements on the list
			last = p;
			last.linkNext(null);

		} else { // In the middle of many

			p.linkNext(n);
			n.linkPrev(p);
		}

		l.linkNext(null);
		l.linkPrev(null);

		size--;

		if (size < 0) {
			final T e = l.linkElement();
			final String name = (e == null) ? null : e.getClass().getSimpleName();
			String msg =
					String.format("size < 0 :: culprit=%s[%s]", name, String.valueOf(e));
			throw new IllegalStateException(msg);
		}
	}

	public synchronized int size() {
		return size;
	}

	public synchronized T get(int index) {
		if (index < 0 || index >= size) {
			throw new IndexOutOfBoundsException(String.format("index=%d, size=%d",
					index,
					size));
		}

		Link<T> l = first;
		int i = 0;
		while (i < index) {
			l = l.linkNext();
			i++;
		}

		return (l == null) ? null : l.linkElement();
	}

	public String toString() {
		StringBuilder b = new StringBuilder();

		b.append('[');
		Link<T> node = first;
		while (node != null) {
			if (node != first) {
				b.append(',');
			}

			b.append(node.toString());

			node = node.linkNext();
		}
		b.append(']');

		return b.toString();
	}
}
