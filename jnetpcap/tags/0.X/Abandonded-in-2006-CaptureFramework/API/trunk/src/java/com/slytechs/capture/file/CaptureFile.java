/**
 * Copyright (C) 2006 Sly Technologies, Inc.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package com.slytechs.capture.file;

import java.io.IOException;
import java.nio.ByteOrder;

import com.slytechs.capture.file.capabilities.PacketCounterModel;
import com.slytechs.utils.number.Version;

/**
 * <P>Main interface to an open capture file. Use the factory
 * method open(File) to get an instance of this interface.</P>
 * 
 * <P>Capture files contain network packet data captured from
 * a network interface and stored in the file. The CaptureFile
 * interface provides an abstraction to the possible formats for
 * capture files. Since different CaptureFiles can contain dramatically
 * different type of information, besides the packet data, depending
 * on what is required, this interface provides a user friendly abstraction
 * with most common features available.</P>
 * 
 * <P>There are two main methods for accessing and possibly modifying the
 * records within the capture file. Using RecordInterator and RecordIndexer interaces.
 * Each interface provides its own specific API that achieve same result but using
 * different level of convenience, capabilities and resources required to achieve
 * the requested outcome.</P>
 * 
 * <P>The preferred method is using the RecordIterator interface which simply
 * iterates over the records within the capture file. The interface provides
 * methods for accessing, skipping, seeking (search + skip), adding and removing
 * records from the capture file. This is the most efficient but least convenient
 * method of accessing contents of a capture file. This method has very little
 * overhead as most records are read from the physical disk on demand. Some caching
 * is used to improve performance especially on peek() and skip() operations.</P>
 * 
 * <P>The second interface is most intuitive and convenient as it uses familiar Collection
 * and List type methods which use indexes instead of iterations over the file. Iterating
 * over the indexed records can also be achieved just as List can be easily iterated in standard
 * Java Collection's Framework. The trade of is that not entire file can be indexed as some file
 * sizes are just too great and only portions of the file at a time should be indexed. Once indexed
 * access to any records is very constant as all the records are cached in memory.</P>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public interface CaptureFile {
	
	public void flush() throws IOException;
	
	public ByteOrder getByteOrder();
	
	/**
	 * Returns the number of packets within the file. This only includes
	 * records that hold packet data and not any additional meta data records.
	 * The method uses the default PacketCounter. If estimated packet counter 
	 * is acceptable you can use one of of several other PacketCounterModels to
	 * calculate estimated packet count using the getPacketCount(PacketCounterModel)
	 * method.
	 * 
	 * @return
	 *   total number of packets within the file using the default model
	 *   
	 * @throws IOException 
	 *   any io errors
	 */
	public long getPacketCount() throws IOException;
	
	/**
	 * Returns the packet count using user requested counter model.
	 * 
	 * @param model
	 *   model to use to count packets
	 *   
	 * @return
	 *   number of packets calculated by the model
	 *   
	 * @throws IOException
	 *   any io exceptions
	 */
	public long getPacketCount(PacketCounterModel model) throws IOException;
	
	/**
	 * Returns file type of the currently open file.
	 * 
	 * @return
	 *   file type of the open capture file
	 */
	public CaptureFileType getType();
	
	/**
	 * Returns the first file version found. There may be
	 * multiple blocks within the file at different versions.
	 *  
	 * @return
	 *   version of the file
	 */
	public abstract Version getVersion();
	
	/**
	 * Returns a higher level iterator that iterates through all of the PacketRecords within
	 * the file. This is typically what the user is interested in. Any meta information 
	 * contained in other types of records is not directly returned as a record but incorporated
	 * into the PacketRecord interface as per its contract.
	 * 
	 * @return
	 *   iterator that iterates through all of the PacketRecords and skips iterations through
	 *   non packet records such as the file header (BlockRecord)
	 * @throws IOException
	 */
	public CaptureIterator<CapturePacket> getPacketIterator() throws IOException;
	
	/**
	 * <P>Returns a low level iterator that will iterate through all of the records within the capture file.
	 * This includes the PacketRecord which contains captured packet data and any other type of 
	 * records present within the file. For example in PCAP capture file, the file also contains
	 * a file header (BlockRecord) which is always returned as the first record within the file.
	 * Other formats such as NAP may return the BlockRecord periodically as multiple BlockRecords
	 * exist in that file format.</P>
	 * 
	 * <P>This method returns the raw records and does not return PacketRecord objects which may contain
	 * meta information not contained in a single record. All the meta records are returned individually 
	 * instead.</P>
	 * 
	 * @return
	 *   iterator that iterates through all the records including the file header (BlockRecord)
	 *   
	 * @throws IOException
	 *   any IO errors
	 */
	public CaptureIterator<Record> getRecordIterator() throws IOException;
	
}
