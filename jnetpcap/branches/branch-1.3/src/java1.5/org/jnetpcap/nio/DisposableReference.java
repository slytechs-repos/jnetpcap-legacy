/**
 * 
 */
package org.jnetpcap.nio;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;


/**
 * A reference, who's data can be disposed of using {@link #dispose()} method
 * invokation. The Reference also implements the Link interface which allows the
 * object to be used in a linked-list of DisposableReference objects managed by
 * {@link LinkSequence} stored in global {@link DisposableGC} object.
 * <p>
 * DisposableReference extends WeakReference functionality by allowing
 * DisposableGC to keep a hardreference to the reference (not the referant) to
 * keep it in memory. Through the use of a {@link ReferenceQueue}, DisposableGC
 * is notified when real objects (referants) are garbage collected. This class
 * only keeps a weak reference to referants, but all cleanup information is also
 * stored in subclass of this class. Specifically by calling on subclassed
 * dispose() method, it allows the subclass to perform cleanup after an object,
 * that has already been deleted from memory. For example JMemoryReference
 * class, deallocates native memory, after the JMemory object that was using
 * that native memory is already gone. The JMemoryReference remains as our
 * subclass and has the address of native memory that needs to be reclaimed.
 * </p>
 * 
 * @author markbe
 * 
 */
public abstract class DisposableReference extends WeakReference<Object>
		implements Disposable, Link<DisposableReference> {

	/*
	 * Since DisposableGC needs to keep a hard reference to us, so that the
	 * DisposableReference part of the Object and Reference combo doesn't get GCed
	 * either, this class implements the Link interface. Its a linked list of
	 * objects that keep references to object before and an object after. This
	 * relationship is maintained by an instance of LinkSequence class in
	 * DisposableGC. This class should not attempt to modify any link fields
	 * directly. All access should be done through a live instance of LinkSequence
	 * class.
	 */
	private final static DisposableGC gc = DisposableGC.getDeault();
	private Link<DisposableReference> linkNext;
	private Link<DisposableReference> linkPrev;

	/**
	 * @param arg0
	 */
	public DisposableReference(Object referant) {
		super(referant, gc.refQueue);

		synchronized (gc.refCollection) {
			gc.refCollection.add(this);
		}

		if (!gc.isCleanupThreadActive()) {
			gc.drainRefQueueBounded();
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetlib.mem.Disposable#dispose()
	 */
	@Override
	public void dispose() {
		// TODO Auto-generated method stub

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetlib.util.Link#linkElement()
	 */
	@Override
	public DisposableReference linkElement() {
		return this;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetlib.util.Link#linkNext()
	 */
	@Override
	public Link<DisposableReference> linkNext() {
		return linkNext;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetlib.util.Link#linkNext(org.jnetlib.util.Link)
	 */
	@Override
	public void linkNext(Link<DisposableReference> l) {
		linkNext = l;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetlib.util.Link#linkPrev()
	 */
	@Override
	public Link<DisposableReference> linkPrev() {
		return linkPrev;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetlib.util.Link#linkPrev(org.jnetlib.util.Link)
	 */
	@Override
	public void linkPrev(Link<DisposableReference> l) {
		linkPrev = l;
	}

	public String toString() {
		return String.format("prev=%s, next=%s", linkPrev, linkNext);
	}

	public void remove() {
		gc.refCollection.remove(this);
		super.clear();
	}
}
