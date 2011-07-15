/*
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010 Sly Technologies, Inc.
 *
 * This file is part of jNetPcap.
 *
 * jNetPcap is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as 
 * published by the Free Software Foundation, either version 3 of 
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.jnetpcap.protocol.voip;

import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JSubHeader;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.packet.annotate.ProtocolSuite;
import org.jnetpcap.protocol.JProtocol;

/**
 * <p>
 * The real-time transport protocol (RTP). RTP provides end-to-end network
 * transport functions suitable for applications transmitting real-time data,
 * such as audio, video or simulation data, over multicast or unicast network
 * services. RTP does not address resource reservation and does not guarantee
 * quality-of-service for real-time services. The data transport is augmented by
 * a control protocol (RTCP) to allow monitoring of the data delivery in a
 * manner scalable to large multicast networks, and to provide minimal control
 * and identification functionality. RTP and RTCP are designed to be independent
 * of the underlying transport and network layers. The protocol supports the use
 * of RTP-level translators and mixers. *
 * </p>
 * <p>
 * Note that RTP itself does not provide any mechanism to ensure timely delivery
 * or provide other quality-of-service guarantees, but relies on lower-layer
 * services to do so. It does not guarantee delivery or prevent out-of-order
 * delivery, nor does it assume that the underlying network is reliable and
 * delivers packets in sequence. The sequence numbers included in RTP allow the
 * receiver to reconstruct the sender's packet sequence, but sequence numbers
 * might also be used to determine the proper location of a packet, for example
 * in video decoding, without necessarily decoding packets in sequence.
 * </p>
 * <p>
 * The RTP header has the following format:
 * 
 * <pre>
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |V=2|P|X|  CC   |M|     PT      |       sequence number         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                           timestamp                           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |           synchronization source (SSRC) identifier            |
 *  +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
 *  |            contributing source (CSRC) identifiers             |
 *  |                             ....                              |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * </pre>
 * 
 * </p>
 * <p>
 * While RTP is primarily designed to satisfy the needs of multi- participant
 * multimedia conferences, it is not limited to that particular application.
 * Storage of continuous data, interactive distributed simulation, active badge,
 * and control and measurement applications may also find RTP applicable.
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header(
		spec = Rtp.RFC,
		suite = ProtocolSuite.VOIP,
		description = Rtp.DESCRIPTION)
public class Rtp extends JHeader {

	/**
	 * An extension mechanism is provided to allow individual implementations to
	 * experiment with new payload-format-independent functions that require
	 * additional information to be carried in the RTP data packet header. This
	 * mechanism is designed so that the header extension may be ignored by other
	 * interoperating implementations that have not been extended. Schulzrinne, et
	 * al. Standards Track [Page 18] RFC 3550 RTP July 2003 Note that this header
	 * extension is intended only for limited use. Most potential uses of this
	 * mechanism would be better done another way, using the methods described in
	 * the previous section. For example, a profile-specific extension to the
	 * fixed header is less expensive to process because it is not conditional nor
	 * in a variable location. Additional information required for a particular
	 * payload format SHOULD NOT use this header extension, but SHOULD be carried
	 * in the payload section of the packet.
	 * 
	 * <pre>
	 * 	  0                   1                   2                   3
	 * 	  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 * 	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * 	 |      defined by profile       |           length              |
	 * 	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * 	 |                        header extension                       |
	 * 	 |                             ....                              |
	 * 
	 * </pre>
	 * 
	 * If the X bit in the RTP header is one, a variable-length header extension
	 * MUST be appended to the RTP header, following the CSRC list if present. The
	 * header extension contains a 16-bit length field that counts the number of
	 * 32-bit words in the extension, excluding the four-octet extension header
	 * (therefore zero is a valid length). Only a single extension can be appended
	 * to the RTP data header. To allow multiple interoperating implementations to
	 * each experiment independently with different header extensions, or to allow
	 * a particular implementation to experiment with more than one type of header
	 * extension, the first 16 bits of the header extension are left open for
	 * distinguishing identifiers or parameters. The format of these 16 bits is to
	 * be defined by the profile specification under which the implementations are
	 * operating. This RTP specification does not define any header extensions
	 * itself.
	 * <p>
	 * This is a baseclass, suitable for use by extending it with the appropriate
	 * extension based on the profile definition. The class defines methods for
	 * reading the static fields that are present in every extension, especially
	 * the {@link #length} field. No sub-header ID needs to be manually assigned
	 * since Rtp specification only allows a single extension to exist within a
	 * header. Note that the profile specific 16-bit field has a getter method
	 * provided but is not marked with <code>Field</code> annotation. This
	 * provides a method for reading the raw 16-bit field value and allows the
	 * subclass to provide its own method that is profile specific and which
	 * possibly further breaks down the structure of this raw field into a
	 * sub-structure.
	 * </p>
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public abstract static class Extension extends JSubHeader<Rtp> {

		/**
		 * Constant which defines the length of the static part of the header in
		 * bytes.
		 */
		public final static int STATIC_HEADER_LENGTH = 4;

		/**
		 * Determines the length of the header in octets. The value is calculated by
		 * use of a 16-bit length field that counts the number of 32-bit words in
		 * the extension.
		 * 
		 * @param buffer
		 *          buffer containing the header data
		 * @param offset
		 *          offset within the buffer of the start of the header
		 * @return length of the header in bytes
		 */
		@HeaderLength
		public static int headerLength(final JBuffer buffer, final int offset) {
			return (buffer.getUShort(2) * 4) + STATIC_HEADER_LENGTH;
		}

		/**
		 * a 16-bit length field that counts the number of 32-bit words in the
		 * extension, excluding the four-octet extension header (therefore zero is a
		 * valid length).
		 * 
		 * @return length of the extension header in 32-bit words, minus the 4 byte
		 *         static part
		 */
		@Field(offset = 2 * BYTE, length = 16)
		public int length() {
			return super.getUShort(2);
		}

		/**
		 * The format of these 16 bit field is to be defined by the profile
		 * specification under which the implementations are operating. This RTP
		 * specification does not define any header extensions itself.
		 * 
		 * @return raw usigned 16 bit value of the profile specific field
		 */
		public int profileSpecific() {
			return super.getUShort(0);
		}
	}

	/**
	 * Generic RTP payload data type.
	 */
	public enum DataType {

		/** The NONE. */
		NONE,

		/** The AUDIO. */
		AUDIO,

		/** The VIDEO. */
		VIDEO,

		/** The AUDI o_ video. */
		AUDIO_VIDEO
	}

	/**
	 * Constant payload types that have been defined for type field.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum PayloadType {

		/**
		 * ITU-T G.711 PCM µ-Law Audio 64 kbit/s (type={@literal G711.type})
		 */
		G711(0, DataType.AUDIO, 1, 8000, 64000, 3551),

		/** reserved, previously CELP Audio 4.8 kbit/s */
		RESERVED1(1, DataType.AUDIO, 1, 8000, 4800, 1890, 3551),

		/** reserved, previously ITU-T G.721 ADPCM Audio 32 kbit/s */
		G721(2, DataType.AUDIO, 1, 8000, 32000, 3551),

		/** European GSM Full Rate Audio 13 kbit/s (GSM 06.10) */
		GSM(3, DataType.AUDIO, 1, 8000, 13000, 1890, 3551),

		/** ITU-T G.723.1 */
		G723(4, DataType.AUDIO, 1, 8000, PayloadType.VARIABLE, 3551),

		/** IMA ADPCM Audio 32 kbit/s */
		DVI4_8K(5, DataType.AUDIO, 1, 8000, 32000, 3551),

		/** IMA ADPCM 64 kbit/s */
		DVI4_16K(6, DataType.AUDIO, 1, 16000, 64000, 3551),

		/** Experimental Linear Predictive Coding Audio */
		LPC(7, DataType.AUDIO, 1, 8000, PayloadType.VARIABLE, 3551),

		/** ITU-T G.711 PCM A-Law Audio 64 kbit/s */
		PCMA(8, DataType.AUDIO, 1, 8000, 64000, 3551),

		/** ITU-T G.722 Audio */
		G722(9, DataType.AUDIO, 1, 8000, PayloadType.VARIABLE, 3551),

		/** uncompressed Linear PCM 16-bit Stereo Audio 1411.2 kbit/s */
		L16_2CH(10, DataType.AUDIO, 2, 44100, 1311200, 3551),

		/** uncompressed Linear PCM 16-bit Audio 705.6 kbit/s */
		L16_1CH(11, DataType.AUDIO, 1, 44100, 705600, 3551),

		/** Qualcomm Code Excited Linear Prediction */
		QCELP(12, DataType.AUDIO, 1, 8000, PayloadType.VARIABLE, 2658, 3551),

		/** Comfort noise */
		CN(13, DataType.AUDIO, 1, 8000, PayloadType.VARIABLE, 3389),

		/** MPEG-1 or MPEG-2 Audio Only */
		MPA(14, DataType.AUDIO, 1, 90000, PayloadType.VARIABLE, 2250, 3551),

		/** ITU-T G.728 Audio 16 kbit/s */
		G728(5, DataType.AUDIO, 1, 8000, 16000, 3551),

		/** IMA ADPCM */
		DVI4_11K(16, DataType.AUDIO, 1, 11025, PayloadType.VARIABLE, 3551),

		/** IMA ADPCM */
		DVI4_22K(17, DataType.AUDIO, 1, 22050, PayloadType.VARIABLE, 3551),

		/** ITU-T G.729 and G.729a */
		G729(18, DataType.AUDIO, 1, 8000, PayloadType.VARIABLE, 3551),

		/** Sun's CellB Video Encoding */
		CELB(25, DataType.VIDEO, 1, 90000, PayloadType.VARIABLE, 2029),

		/** JPEG Video */
		JPEG(26, DataType.VIDEO, 1, 90000, PayloadType.VARIABLE, 2435),

		/** Xerox PARC's Network Video (nv) */
		NV(28, DataType.VIDEO, 1, 90000, PayloadType.VARIABLE, 3551),

		/** ITU-T H.261 Video */
		H261(31, DataType.VIDEO, 1, 90000, PayloadType.VARIABLE, 4587),

		/** MPEG-1 and MPEG-2 Video */
		MPV(32, DataType.VIDEO, 1, 90000, PayloadType.VARIABLE, 2250),

		/** MPEG-2 transport stream Video */
		MP2T(33, DataType.AUDIO_VIDEO, 1, 90000, PayloadType.VARIABLE, 2250),

		/** H.263 video, first version (1996) */
		H263(35, DataType.VIDEO, 1, 90000, PayloadType.VARIABLE, 2190, 3551),

		/** H.263 video, second version (1998) */
		H263_1998(PayloadType.VARIABLE, DataType.VIDEO, 1, 90000,
				PayloadType.VARIABLE, 2190, 4629, 3551),

		/** H.263 video, third version (2000) */
		H263_2000(PayloadType.VARIABLE, DataType.VIDEO, 1, 90000,
				PayloadType.VARIABLE, 4629),

		/** H.264 video (MPEG-4 Part 10) */
		H264(PayloadType.VARIABLE, DataType.VIDEO, 1, 90000, PayloadType.VARIABLE,
				3984),

		/** Theora video */
		THEORA(PayloadType.VARIABLE, DataType.VIDEO, 1, 90000,
				PayloadType.VARIABLE, "draft-barbato-avt-rtp-theora-01"),

		/** Internet low Bitrate Codec 13.33 or 15.2 kbit/s */
		ILBC(PayloadType.VARIABLE, DataType.AUDIO, 1, PayloadType.VARIABLE,
				PayloadType.VARIABLE, 3951),

		/** ITU-T G.711.1, A-law */
		PCMA_WB_ALAW(PayloadType.VARIABLE, DataType.AUDIO, 1, 16000,
				PayloadType.VARIABLE, 5391),

		/** ITU-T G.711.1, µ-law */
		PCMA_WB_ULAW(PayloadType.VARIABLE, DataType.AUDIO, 1, 16000,
				PayloadType.VARIABLE, 5391),

		/** ITU-T G.718 */
		G718(PayloadType.VARIABLE, DataType.AUDIO, 1, 32000, PayloadType.VARIABLE,
				"draft-ietf-avt-rtp-g718-03"),

		/** ITU-T G.719 */
		G719(PayloadType.VARIABLE, DataType.AUDIO, PayloadType.VARIABLE, 48000,
				PayloadType.VARIABLE, 5404),

		/** ITU-T G.722.1 */
		G7221(PayloadType.VARIABLE, DataType.AUDIO, PayloadType.VARIABLE,
				PayloadType.VARIABLE, PayloadType.VARIABLE, 5577),

		/** ITU-T G.726 audio with 16 kbit/s */
		G726_16(PayloadType.VARIABLE, DataType.AUDIO, 1, 8000, 16000, 3551),

		/** ITU-T G.726 audio with 24 kbit/s */
		G726_24(PayloadType.VARIABLE, DataType.AUDIO, 1, 8000, 24000, 3551),

		/** ITU-T G.726 audio with 32 kbit/s */
		G726_32(PayloadType.VARIABLE, DataType.AUDIO, 1, 8000, 32000, 3551),

		/** ITU-T G.726 audio with 40 kbit/s */
		G726_40(PayloadType.VARIABLE, DataType.AUDIO, 1, 8000, 40000, 3551),

		/** ITU-T G.729 Annex D */
		G729D(PayloadType.VARIABLE, DataType.AUDIO, 1, 8000, PayloadType.VARIABLE,
				3551),

		/** ITU-T G.729 Annex E */
		G729E(PayloadType.VARIABLE, DataType.AUDIO, 1, 8000, PayloadType.VARIABLE,
				3551),

		/** ITU-T G.729.1 */
		G7291(PayloadType.VARIABLE, DataType.AUDIO, 1, PayloadType.VARIABLE,
				PayloadType.VARIABLE, 3551),

		/** ITU-T GSM-EFR (GSM 06.60) */
		GSM_EFR(PayloadType.VARIABLE, DataType.AUDIO, 1, PayloadType.VARIABLE,
				PayloadType.VARIABLE, 3551),

		/** ITU-T GSM-HR (GSM 06.20) */
		GSM_HR_08(PayloadType.VARIABLE, DataType.AUDIO, 1, PayloadType.VARIABLE,
				PayloadType.VARIABLE, 5993),

		/** Adaptive Multi-Rate audio */
		AMR(PayloadType.VARIABLE, DataType.AUDIO, 1, 8000, PayloadType.VARIABLE,
				4867),

		/** Adaptive Multi-Rate Wideband audio (ITU-T G.722.2) */
		AMR_WB(PayloadType.VARIABLE, DataType.AUDIO, 1, 16000,
				PayloadType.VARIABLE, 4867),

		/** Extended Adaptive Multi Rate – WideBand audio */
		AMR_WB_PLUS(PayloadType.VARIABLE, DataType.AUDIO, PayloadType.VARIABLE,
				72000, PayloadType.VARIABLE, 4352),

		/** RTP Payload Format for Vorbis Encoded Audio */
		VORBIS(PayloadType.VARIABLE, DataType.AUDIO, PayloadType.VARIABLE,
				PayloadType.VARIABLE, PayloadType.VARIABLE, 5215),

		/** RTP Payload Format for the Speex Codec */
		SPEEX(PayloadType.VARIABLE, DataType.AUDIO, PayloadType.VARIABLE,
				PayloadType.VARIABLE, PayloadType.VARIABLE, 5574),

		/** Linear PCM 16-bit audio */
		L16(PayloadType.VARIABLE, DataType.AUDIO, PayloadType.VARIABLE,
				PayloadType.VARIABLE, PayloadType.VARIABLE, 3190),

		/** Linear PCM 20-bit audio */
		L20(PayloadType.VARIABLE, DataType.AUDIO, PayloadType.VARIABLE,
				PayloadType.VARIABLE, PayloadType.VARIABLE, 3190),

		/** Linear PCM 24-bit audio */
		L24(PayloadType.VARIABLE, DataType.AUDIO, PayloadType.VARIABLE,
				PayloadType.VARIABLE, PayloadType.VARIABLE, 3190),

		/** UKNOWN RTP TYPELOAD TYPE. A catchall constant. */
		UNKNOWN(PayloadType.VARIABLE, DataType.NONE, PayloadType.VARIABLE,
				PayloadType.VARIABLE, PayloadType.VARIABLE, new int[0]),

		//
		/** The Constant VARIABLE. */
		;

		/**
		 * A flag that indicates that a particular value is either variable,
		 * undefined or unknown within the PayloadType table.
		 */
		public final static int VARIABLE = -1;

		/** RTP payload type value or -1 if variable or unknown. */
		public final int type;

		/**
		 * Generic data type, AUDIO, VIDEO or AUDIO/VIDEO, NONE if none defined.
		 */
		public final DataType data;

		/** Number of channels or -1 if variable or unknown. */
		public final int channels;

		/** Clock rate in hertz or -1 if variable or unknown. */
		public final int clock;

		/** Base 10 bit rate in bits/second or -1 if unknown. */
		public final int rate;

		/**
		 * An array of specifications that are related to or define this PayloadType
		 * codec.
		 */
		public final String[] specs;

		/**
		 * Instantiates a new payload type.
		 * 
		 * @param type
		 *          RTP payload type value or -1 if variable or unknown
		 * @param data
		 *          generic data type, AUDIO, VIDEO or AUDIO/VIDEO, NONE if none
		 *          defined
		 * @param channels
		 *          number of channels or -1 if variable or unknown
		 * @param clock
		 *          clock rate in hertz or -1 if variable or unknown
		 * @param rate
		 *          base 10 bit rate in bits/second or -1 if unknown
		 * @param rfcs
		 *          a list of rfc numbers
		 */
		private PayloadType(int type, DataType data, int channels, int clock,
				int rate, int... rfcs) {
			this.type = type;
			this.data = data;
			this.channels = channels;
			this.clock = clock;
			this.rate = rate;
			this.specs = new String[rfcs.length];

			for (int i = 0; i < rfcs.length; i++) {
				this.specs[i] = "RFC" + rfcs[i];
			}
		}

		/**
		 * Instantiates a new payload type.
		 * 
		 * @param type
		 *          RTP payload type value or -1 if variable or unknown
		 * @param data
		 *          generic data type, AUDIO, VIDEO or AUDIO/VIDEO, NONE if none
		 *          defined
		 * @param channels
		 *          number of channels or -1 if variable or unknown
		 * @param clock
		 *          clock rate in hertz or -1 if variable or unknown
		 * @param rate
		 *          base 10 bit rate in bits/second or -1 if unknown
		 * @param specs
		 *          a list of specifications that define or are related to this
		 *          constant
		 */
		private PayloadType(int type, DataType data, int channels, int clock,
				int rate, String... specs) {
			this.type = type;
			this.data = data;
			this.channels = channels;
			this.clock = clock;
			this.rate = rate;
			this.specs = specs;

		}

		/**
		 * Looks up the payload type as integer and returns a constant.
		 * 
		 * @param type
		 *          value of the payload field
		 * @return Constant representing the payload type or UNKNOWN if type is not
		 *         defined in the table. This method never returns null.
		 */
		public static PayloadType valueOf(final int type) {
			for (PayloadType t : values()) {
				if (t.type == type) {
					return t;
				}
			}

			return PayloadType.UNKNOWN;
		}

		/**
		 * Gets a list of constant by clock rate.
		 * 
		 * @param clock
		 *          the clock
		 * @return the payload type[]
		 */
		public static PayloadType[] valuesByClockRate(int clock) {
			List<PayloadType> list = new ArrayList<PayloadType>();

			for (PayloadType t : values()) {
				if (t.clock == clock) {
					list.add(t);
				}
			}

			return list.toArray(new PayloadType[list.size()]);
		}

		/**
		 * Gets a list of constants by data type (AUDIO, VIDEO, AUDIO_VIDEO).
		 * 
		 * @param type
		 *          the type
		 * @return the payload type[]
		 */
		public static PayloadType[] valuesByDataType(DataType type) {
			List<PayloadType> list = new ArrayList<PayloadType>();

			for (PayloadType t : values()) {
				if (t.data == type) {
					list.add(t);
				}
			}

			return list.toArray(new PayloadType[list.size()]);
		}

		/**
		 * Gets a list of constants by channel count.
		 * 
		 * @param count
		 *          the count
		 * @return the payload type[]
		 */
		public static PayloadType[] valuesByChannelCount(int count) {
			List<PayloadType> list = new ArrayList<PayloadType>();

			for (PayloadType t : values()) {
				if (t.channels == count) {
					list.add(t);
				}
			}

			return list.toArray(new PayloadType[list.size()]);
		}
	}

	/**
	 * Bitmask applied to byte 0 in the header which masks off the CSRC COUNT
	 * field.
	 */
	public final static int CC_MASK = 0x0F;

	/**
	 * Bit offset into byte 0 of the header for CSRC COUNT field.
	 */
	public final static int CC_OFFSET = 0;

	/** Constant which defines the length of a CSRC entry in CSRC table in bytes. */
	public final static int CSRC_LENGTH = 4;

	/** Constant containing a short description of this protocol header. */
	public final static String DESCRIPTION = "real-time transfer protocol";

	/**
	 * Bitmask applied to byte 0 in the header which masks off the extension bit
	 * option flag.
	 */
	public final static int EXTENSION_MASK = 0x10;

	/**
	 * Bit offset into byte 0 of the header for EXTENSION field.
	 */
	public final static int EXTENSION_OFFSET = 4;

	/** Registry assigned header ID. */
	public static int ID = JProtocol.RTP_ID;

	/**
	 * Bitmask applied to byte 1 in the header which masks off the marker bit
	 * option flag.
	 */
	public final static int MARKER_MASK = 0x80;

	/**
	 * Bit offset into byte 1 of the header for MARKER field.
	 */
	public final static int MARKER_OFFSET = 7;

	/**
	 * Bitmask applied to byte 0 in the header which masks off the padding bit
	 * option flag.
	 */
	public final static int PADDING_MASK = 0x20;

	/**
	 * Bit offset into byte 0 of the header for PADDING field.
	 */
	public final static int PADDING_OFFSET = 5;

	/**
	 * Constant containing the name of the RFC that describes the specification of
	 * this header.
	 */
	public final static String RFC = "rfc3550";

	/** Default RTP port number. */
	public final static int RTP_UDP_PORT = 5004;

	/**
	 * Constant which defines the length of the static part of the header in
	 * bytes.
	 */
	public final static int STATIC_HEADER_LENGTH = 12;

	/** Constant containing the name of the protocol suite this header belongs to. */
	public final static ProtocolSuite SUITE = ProtocolSuite.VOIP;

	/**
	 * Bitmask applied to byte 1 in the header which masks off the payload type
	 * field.
	 */
	public final static int TYPE_MASK = 0x7F;

	/**
	 * Bit offset into byte 1 of the header for PAYLOAD TYPE field.
	 */
	public final static int TYPE_OFFSET = 0;

	/**
	 * Bitmask applied to byte 0 in the header which masks off the version number
	 * of the Rtp header within the packet.
	 */
	public final static int VERSION_MASK = 0xC0;

	/**
	 * Bit offset into byte 0 of the header for VERSION field.
	 */
	public final static int VERSION_OFFSET = 6;

	/**
	 * Calculate the base header length (Rtp header without an extension).
	 * 
	 * @param buffer
	 *          buffer with rtp header
	 * @param offset
	 *          offset into the buffer
	 * @return dynamic length of the header with extension ignored
	 */
	private static int baseHeaderLength(final JBuffer buffer, final int offset) {
		final byte b0 = buffer.getByte(offset);
		final int cc = (b0 & CC_MASK) >> CC_OFFSET;

		return Rtp.STATIC_HEADER_LENGTH + (cc * CSRC_LENGTH);
	}

	/**
	 * Determines the length of the header in octets. The value is calculated by
	 * adding to the length of the static part of the header the length of the
	 * CSRC table. The CC field contains number of 32-bit entries within the
	 * table.
	 * 
	 * @param buffer
	 *          buffer containing the header data
	 * @param offset
	 *          offset within the buffer of the start of the header
	 * @return length of the header in bytes
	 */

	@HeaderLength
	public static int headerLength(final JBuffer buffer, final int offset) {
		final int rtpBaseHeader = baseHeaderLength(buffer, offset);

		if ((buffer.getByte(offset) & EXTENSION_MASK) > 0) {
			return rtpBaseHeader
					+ Rtp.Extension.headerLength(buffer, offset + rtpBaseHeader);
		} else {
			return rtpBaseHeader;
		}
	}

	/**
	 * Determines the length of Rtp padding if the header has been padded. If the
	 * Rtp.P bit is set, that means that last byte within the frame contains the
	 * number of bytes that were used to pad after the payload following this
	 * header.
	 * 
	 * @param buffer
	 *          buffer to read options and padding information from
	 * @param offset
	 *          offset to the start of the header
	 * @return number of bytes padding rtp payload or 0 if no padding bytes
	 */
	@HeaderLength(HeaderLength.Type.POSTFIX)
	public static int postfixLength(final JBuffer buffer, final int offset) {
		if ((buffer.getByte(offset) & PADDING_MASK) > 0) {
			return buffer.getUByte(buffer.size() - 1);
		} else {
			return 5;
		}
	}

	/**
	 * The CSRC count contains the number of CSRC identifiers that follow the
	 * fixed header.
	 * 
	 * @return number of 4 octect CSRC identifiers that follow the fixed header
	 *         part
	 */
	@Field(offset = 4, length = 4)
	public int count() {
		return (super.getByte(0) & CC_MASK) >> CC_OFFSET;
	}

	/**
	 * <p>
	 * The CSRC list identifies the contributing sources for the payload contained
	 * in this packet. The number of identifiers is given by the CC field. If
	 * there are more than 15 contributing sources, only 15 can be identified.
	 * CSRC identifiers are inserted by mixers (see Section 7.1), using the SSRC
	 * identifiers of contributing sources. For example, for audio packets the
	 * SSRC identifiers of all sources that were mixed together to create a packet
	 * are listed, allowing correct talker indication at the receiver.
	 * </p>
	 * 
	 * @return array which contains values of the csrc list field
	 */
	@Field(offset = STATIC_HEADER_LENGTH * BYTE)
	public int[] csrc() {
		final int count = count();

		final int[] csrc = new int[count];

		for (int i = 0; i < csrc.length; i++) {
			csrc[i] = super.getInt(STATIC_HEADER_LENGTH + i * CSRC_LENGTH);
		}

		return csrc;
	}

	/**
	 * Calculates the length of the csrc field in bits. The length is calculated
	 * by using the count (CC) field and multiplying by 32 bits which is the
	 * length of each CSRC entry.
	 * 
	 * @return length of the csrc field in bits
	 */
	@Dynamic(Field.Property.LENGTH)
	public int csrcLength() {
		return count() * CSRC_LENGTH * BYTE;
	}

	/**
	 * If the extension bit is set, the fixed header MUST be followed by exactly
	 * one header extension, with a format defined in Section 5.3.1 of RFC3550
	 * 
	 * @return value of the extension field
	 */
	@Field(offset = 3, length = 1)
	public boolean hasExtension() {
		return ((super.getByte(0) & EXTENSION_MASK) >> EXTENSION_OFFSET) > 0;
	}

	/**
	 * The interpretation of the marker is defined by a profile. It is intended to
	 * allow significant events such as frame boundaries to be marked in the
	 * packet stream. A profile MAY define additional marker bits or specify that
	 * there is no marker bit by changing the number of bits in the payload type
	 * field (see Section 5.3 of RFC3550).
	 * 
	 * @return value of the marker field
	 */
	@Field(offset = 8, length = 1)
	public boolean hasMarker() {
		return ((super.getByte(1) & MARKER_MASK) >> MARKER_OFFSET) > 0;
	}

	/**
	 * If the padding bit is set, the packet contains one or more additional
	 * padding octets at the end which are not part of the payload. The last octet
	 * of the padding contains a count of how many padding octets should be
	 * ignored, including itself. Padding may be needed by some encryption
	 * algorithms with fixed block sizes or for carrying several RTP packets in a
	 * lower-layer protocol data unit.
	 * 
	 * @return value of the padding field
	 */
	@Field(offset = 2, length = 1)
	public boolean hasPadding() {
		return ((super.getByte(0) & PADDING_MASK) >> PADDING_OFFSET) > 0;
	}

	/**
	 * Returns the number of padding bytes that were appended at the end of this
	 * Rtp frame.
	 * 
	 * @return number of padding bytes
	 */
	public int paddingLength() {
		if (hasPostfix() == false) {
			return 0;
		}

		final int length =
				this.packet.getUByte(getPostfixOffset() + getPostfixLength() - 1);

		return length;
	}

	/**
	 * The sequence number increments by one for each RTP data packet sent, and
	 * may be used by the receiver to detect packet loss and to restore packet
	 * sequence. The initial value of the sequence number SHOULD be random
	 * (unpredictable) to make known-plaintext attacks on encryption more
	 * difficult, even if the source itself does not encrypt according to the
	 * method in Section 9.1 of RFC3550, because the packets may flow through a
	 * translator that does.
	 * 
	 * @return value of the sequence number field
	 */
	@Field(offset = 16, length = 16)
	public int sequence() {
		return super.getUShort(2);
	}

	/**
	 * The SSRC field identifies the synchronization source. This identifier
	 * SHOULD be chosen randomly, with the intent that no two synchronization
	 * sources within the same RTP session will have the same SSRC identifier. An
	 * example algorithm for generating a random identifier is presented in
	 * Appendix A.6. Although the probability of multiple sources choosing the
	 * same identifier is low, all RTP implementations must be prepared to detect
	 * and resolve collisions. Section 8 describes the probability of collision
	 * along with a mechanism for resolving collisions and detecting RTP-level
	 * forwarding loops based on the uniqueness of the SSRC identifier. If a
	 * source changes its source transport address, it must also choose a new SSRC
	 * identifier to avoid being interpreted as a looped source (see Section 8.2).
	 * 
	 * @return value of the unsigned 32-bit ssrc field
	 */
	@Field(offset = 8 * BYTE, length = 32)
	public long ssrc() {
		return super.getUInt(8);
	}

	/**
	 * <p>
	 * The timestamp reflects the sampling instant of the first octet in the RTP
	 * data packet. The sampling instant MUST be derived from a clock that
	 * increments monotonically and linearly in time to allow synchronization and
	 * jitter calculations (see Section 6.4.1). The resolution of the clock MUST
	 * be sufficient for the desired synchronization accuracy and for measuring
	 * packet arrival jitter (one tick per video frame is typically not
	 * sufficient). The clock frequency is dependent on the format of data carried
	 * as payload and is specified statically in the profile or payload format
	 * specification that defines the format, or MAY be specified dynamically for
	 * payload formats defined through non-RTP means. If RTP packets are generated
	 * periodically, the nominal sampling instant as determined from the sampling
	 * clock is to be used, not a reading of the system clock. As an example, for
	 * fixed-rate audio the timestamp clock would likely increment by one for each
	 * sampling period. If an audio application reads blocks covering 160 sampling
	 * periods from the input device, the timestamp would be increased by 160 for
	 * each such block, regardless of whether the block is transmitted in a packet
	 * or dropped as silent.
	 * </p>
	 * </p> The initial value of the timestamp SHOULD be random, as for the
	 * sequence number. Several consecutive RTP packets will have equal timestamps
	 * if they are (logically) generated at once, e.g., belong to the same video
	 * frame. Consecutive RTP packets MAY contain timestamps that are not
	 * monotonic if the data is not transmitted in the order it was sampled, as in
	 * the case of MPEG interpolated video frames. (The sequence numbers of the
	 * packets as transmitted will still be monotonic.) </p> </p> RTP timestamps
	 * from different media streams may advance at different rates and usually
	 * have independent, random offsets. Therefore, although these timestamps are
	 * sufficient to reconstruct the timing of a single stream, directly comparing
	 * RTP timestamps from different media is not effective for synchronization.
	 * Instead, for each medium the RTP timestamp is related to the sampling
	 * instant by pairing it with a timestamp from a reference clock (wallclock)
	 * that represents the time when the data corresponding to the RTP timestamp
	 * was sampled. The reference clock is shared by all media to be synchronized.
	 * The timestamp pairs are not transmitted in every data packet, but at a
	 * lower rate in RTCP SR packets as described in Section 6.4. </p> </p> The
	 * sampling instant is chosen as the point of reference for the RTP timestamp
	 * because it is known to the transmitting endpoint and has a common
	 * definition for all media, independent of encoding delays or other
	 * processing. The purpose is to allow synchronized presentation of all media
	 * sampled at the same time. </p> </p> Applications transmitting stored data
	 * rather than data sampled in real time typically use a virtual presentation
	 * timeline derived from wallclock time to determine when the next frame or
	 * other unit of each medium in the stored data should be presented. In this
	 * case, the RTP timestamp would reflect the presentation time for each unit.
	 * That is, the RTP timestamp for each unit would be related to the wallclock
	 * time at which the unit becomes current on the virtual presentation
	 * timeline. Actual presentation occurs some time later as determined by the
	 * receiver. </p> </p> An example describing live audio narration of
	 * prerecorded video illustrates the significance of choosing the sampling
	 * instant as the reference point. In this scenario, the video would be
	 * presented locally for the narrator to view and would be simultaneously
	 * transmitted using RTP. The "sampling instant" of a video frame transmitted
	 * in RTP would be established by referencing its timestamp to the wallclock
	 * time when that video frame was presented to the narrator. The sampling
	 * instant for the audio RTP packets containing the narrator's speech would be
	 * established by referencing the same wallclock time when the audio was
	 * sampled. The audio and video may even be transmitted by different hosts if
	 * the reference clocks on the two hosts are synchronized by some means such
	 * as NTP. A receiver can then synchronize presentation of the audio and video
	 * packets by relating their RTP timestamps using the timestamp pairs in RTCP
	 * SR packets. </p>
	 * 
	 * @return value of the unsigned 32-bit timestamp field
	 */
	@Field(offset = 4 * BYTE, length = 32)
	public long timestamp() {
		return super.getUInt(4);
	}

	/**
	 * This field identifies the format of the RTP payload and determines its
	 * interpretation by the application. A profile MAY specify a default static
	 * mapping of payload type codes to payload formats. Additional payload type
	 * codes MAY be defined dynamically through non-RTP means (see Section 3). A
	 * set of default mappings for audio and video is specified in the companion
	 * RFC 3551 [1]. An RTP source MAY change the payload type during a session,
	 * but this field SHOULD NOT be used for multiplexing separate media streams
	 * (see Section 5.2 of RFC3550). A receiver MUST ignore packets with payload
	 * types that it does not understand.
	 * 
	 * @return value of the payload type field
	 */
	@Field(offset = 9, length = 7)
	public int type() {
		return (super.getByte(1) & TYPE_MASK) >> TYPE_OFFSET;
	}

	/**
	 * This field identifies the format of the RTP payload and determines its
	 * interpretation by the application. A profile MAY specify a default static
	 * mapping of payload type codes to payload formats. Additional payload type
	 * codes MAY be defined dynamically through non-RTP means (see Section 3). A
	 * set of default mappings for audio and video is specified in the companion
	 * RFC 3551 [1]. An RTP source MAY change the payload type during a session,
	 * but this field SHOULD NOT be used for multiplexing separate media streams
	 * (see Section 5.2 of RFC3550). A receiver MUST ignore packets with payload
	 * types that it does not understand.
	 * 
	 * @return value of the payload type field as a constant
	 */
	public PayloadType typeEnum() {
		return PayloadType.valueOf(type());
	}

	/**
	 * This field identifies the version of RTP. The version defined by this
	 * specification is two (2). (The value 1 is used by the first draft version
	 * of RTP and the value 0 is used by the protocol initially implemented in the
	 * "vat" audio tool.)
	 * 
	 * @return version number of rtp header
	 */
	@Field(offset = 0, length = 2)
	public int version() {
		return (super.getByte(0) & VERSION_MASK) >> VERSION_OFFSET;
	}

	/**
	 * Gets the Rtp packet's payload.
	 * 
	 * @return buffer containing payload that is right after this Rtp header
	 */
	// public byte[] payload() {
	// return packet.getByteArray(getPayloadOffset(), getPayloadLength());
	// }
}
