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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteOrder;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
 * <P>To inquire what is capable with a given file format, you can query 
 * for capabilities of the capture file using the 
 * CaptureFile.getCapabilities(): Set<Capability> method. Also note that
 * records also provide their own capabilities Set, use the 
 * Record.getCapabilities(): Set<Capability> to inquire about individual record
 * capabilities. For example, NAP and SNOOP file formats are capable of storing
 * interface counters along with packet data, while PCAP is not.</P>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class CaptureFile {
	
	private static Map<CaptureFileType, CaptureFileHandler> handlers = new HashMap<CaptureFileType, CaptureFileHandler>();
	
	/**
	 * Concatenate all the files into the 
	 * @param file1
	 * @param files
	 * @return
	 */
	public static boolean catFile(File file1, File ... files) {
		return false;
	}
	
	/**
	 * Cleans up and compacts the file contents to most efficient size and layout.
	 * 
	 * @param file
	 *   file to compact
	 *   
	 * @return
	 *   true if successfull, otherwise false
	 */
	public static boolean compactFile(File file) {
		return false;
	}
	
	/**
	 * Returns a mutable map of currently registerd capture file handlers. The default map is populated with
	 * handlers defined by the SuppliedFileTypes enum structure.
	 * 
	 * @return
	 *   map of registered handlers for capture file format
	 */
	public static Map<CaptureFileType, CaptureFileHandler> getHandlers() {
		if (handlers.isEmpty()) {
			for (CaptureFileType type: SuppliedFileTypes.values()) {
				handlers.put(type, type.getDefaultHandler());
			}
		}
		
		return handlers;
	}
	
	/**
	 * Returns file type of the specified file. File will be opened
	 * and its type verified.
	 * 
	 * @return
	 *   file type of a capture file
	 * @throws FileNotFoundException 
	 * @throws IOException 
	 */
	public static CaptureFileType getType(File file) throws FileNotFoundException, IOException {
		return null;
	}
	
	public static CaptureFile newFile(File file, SuppliedFileTypes type) {
		return null;
	}
	
	public static CaptureFile newFile(File file, SuppliedFileTypes type, Version version) {
		return null;
	}
	
	public static CaptureFile newFile(File file, SuppliedFileTypes type, Version version, ByteOrder encoding) {
		return null;
	}
	
	public static CaptureFile openFile(File file) {
		return null;
	}
	
	/**
	 * <P>Splits the file into smaller files according to default rules defined for each
	 * file format. For NAP the file will be split with each Block Record being split
	 * into its own seperate file. For other files, the defaults are to split the files
	 * into 512Kb files.</P>
	 * 
	 * <P>The base filename supplied is used as the base filename for all newly created files
	 * with the -XXXX appended to them.<P>
	 * 
	 * <P>The source file is unmodified</p>
	 * 
	 * @param file
	 *   file to be split
	 *   
	 * @return
	 *   list of newly created files 
	 */
	public static List<File> splitFile(File file) {
		return null;
	}
	
	/**
	 * <P>Split the specified file into smaller files containing specified number of packets
	 * each from the source file. New files are created to hold only the specified number
	 * of packets and associated meta records. The supplied filename is used as a base filename
	 * for all newly created files with the post fix of -XXXX appended to them.</P>
	 * 
	 * <P>The source file is unmodified</P>
	 * 
	 * @param file
	 *   source file to split
	 *   
	 * @param packetCount
	 *   split using this many packets from the source file copied into the newly created files
	 *   
	 * @param maxCompression
	 *   true means produce the smallest possible file, while false means leave it upto the default
	 *   algorithm for each spcific file type. For example NAP files pad their files to 512Kb by default
	 *   which means that files containing even only a single packet are of minimum size 512 Kb, but this
	 *   can be overriden by setting maxCompression to true. Notice that it will be harder to split the NAP file
	 *   with regular unix commands if default padding is not used.
	 *   
	 * @return
	 *   list of all the new files created
	 */
	public static List<File> splitFile(File file, long packetCount, boolean maxCompression) {
		return null;
	}
	
	/**
	 * Determines the file type of the supplied file. This similar method to the dynamic counter
	 * part CaptureFile.getType(), but does not require the file to be opened before hand and
	 * is quicker then using CaptureFile.openFile().getType() sequence. As more specific algorithm
	 * is used.
	 * 
	 * @param file
	 *   file to check and return file type
	 *   
	 * @return
	 *   file type of the supplied file or null if file type unknown or not supported
	 */
	public static CaptureFileType typeOfFile(File file) {
		return null;
	}

	/**
	 * Checks if the specified file is in a proper format 100% compabile with 
	 * specification.
	 * 
	 * @param file
	 *   file to validate
	 *   
	 * @return
	 *   true if file is valid with the specification, otherwise false, even if
	 *   minor infringements are found
	 */
	public static boolean validateFile(File file) {
		return false;
	}
	
	public abstract void flush() throws IOException;
	
	public abstract ByteOrder getByteOrder();
	
	/**
	 * Returns the number of packets within the file. This only includes
	 * records that hold packet data and not any additional meta data records.
	 * 
	 * @return
	 *   total number of packets within the file
	 * @throws IOException 
	 */
	public abstract long getPacketCount() throws IOException;
	
	/**
	 * The list of all packet records within this capture file. Some meta information is
	 * also supplied with the PacketRecords which in actuality is a read from other meta
	 * records. This information is combined for convenience of the user. If raw record support
	 * is required use the getDataRecords() or getAllRecords() method calls which supply unaltered
	 * raw records.
	 * 
	 * @return
	 */
	public abstract List<? extends PacketRecord> getPacketRecords();
	

	
	/**
	 * Returns file type of the currently open file.
	 * 
	 * @return
	 *   file type of the open capture file
	 */
	public abstract CaptureFileType getType();
	
	/**
	 * Returns the first file version found. There may be
	 * multiple blocks within the file at different versions.
	 *  
	 * @return
	 *   version of the file
	 */
	public abstract Version getVersion();
}
