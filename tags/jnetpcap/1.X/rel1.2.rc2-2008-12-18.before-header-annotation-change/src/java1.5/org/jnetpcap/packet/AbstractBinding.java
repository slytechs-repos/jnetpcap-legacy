/**
 * Copyright (C) 2008 Sly Technologies, Inc. This library is free
 * software; you can redistribute it and/or modify it under the terms
 * of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version. This library is distributed in the hope
 * that it will be useful, but WITHOUT ANY WARRANTY; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU Lesser General Public License for more
 * details. You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */
package org.jnetpcap.packet;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class AbstractBinding
    implements JBinding {

  protected int[] dependencies;

  private int sourceId;

  private int targetId;

  private final Class<? extends JHeader> targetClass;

  protected AbstractBinding(Class<? extends JHeader> targetClass) {
    this.targetClass = targetClass;

  }

  public Class<? extends JHeader> getTargetClass() {
    return targetClass;
  }

  /*
   * (non-Javadoc)
   * 
   * @see org.jnetpcap.packet.JBinding#getTargetId()
   */
  public int getTargetId() {
    return targetId;
  }

  /*
   * (non-Javadoc)
   * 
   * @see org.jnetpcap.packet.JDependency#getId()
   */
  public int getId() {
    return sourceId;
  }

  /*
   * (non-Javadoc)
   * 
   * @see org.jnetpcap.packet.JDependency#listDependencies()
   */
  public int[] listDependencies() {
    return dependencies;
  }

  public int scanForNextHeader(JPacket packet, int offset) {
    return scan(packet, offset);
  }
  
  protected abstract int scan(JPacket packet, int offset);

}
