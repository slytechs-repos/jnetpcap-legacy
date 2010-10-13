/**
 * 
 */
package org.jnetpcap.nio;

/**
 * 
 * @author markbe
 * 
 * @param <T>
 */
public interface Link<T> {
	public Link<T> linkNext();

	public void linkNext(Link<T> l);

	public Link<T> linkPrev();

	public void linkPrev(Link<T> l);

	public T linkElement();
}
