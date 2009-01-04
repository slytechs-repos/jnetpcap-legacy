package org.jnetpcap.util.resolver;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.logging.Level;

import org.jnetpcap.packet.format.JFormatter;
import org.jnetpcap.util.JLogger;
import org.jnetpcap.util.config.JConfig;

/**
 * A resolver that resolves the first 3 bytes of a MAC address to a manufacturer
 * code. The resolver loads jNetPcap supplied compressed oui database of
 * manufacturer codes and caches that information. The resolver can also
 * download over the internet, if requested, a raw IEEE OUI database of
 * manufacturer code, parse it and produce a cache file for future use.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class IEEEOuiPrefixResolver
    extends AbstractResolver {

	/**
	 * Default URI path to IEEE raw oui database of manufacturer codes. The URI is
	 * {@value #IEEE_OUI_DATABASE_PATH}.
	 */
	public final static String IEEE_OUI_DATABASE_PATH =
	    "http://standards.ieee.org/regauth/oui/oui.txt";

	private static final String RESOURCE_COMPRESSED_OUI_DATABASE = "oui.txt";

	private static final String PROPERTY_OUI_DB_URL =
	    "resolver.OUI_PREFIX.db.url";

	private static final String PROPERTY_OUI_DB_DOWNLOAD =
	    "resolver.OUI_PREFIX.db.download";

	private static final String DEFAULT_OUI_DB_DOWNLOAD = "false";

	private boolean initialized = false;

	/**
	 * Creates an uninitalized Oui prefix resolver. The resolver is "late"
	 * initialized when its first called on to do work.
	 * 
	 * @param type
	 */
	public IEEEOuiPrefixResolver() {
		super(JLogger.getLogger(IEEEOuiPrefixResolver.class), "OUI_PREFIX");
	}

	/**
	 * Initializes the resolver by first checking if there are any cached entries,
	 * if none, it reads the compressed oui database supplied with jNetPcap in the
	 * resource directory {@value #RESOURCE_COMPRESSED_OUI_DATABASE}.
	 */
	@Override
	public void initializeIfNeeded() {
		if (initialized == false && hasCacheFile() == false) {
			initialized = true;

			setCacheCapacity(13000); // There are over 12,000 entries in the db
			
			super.initializeIfNeeded(); // Allow the baseclass to prep cache
			
			setPositiveTimeout(INFINITE_TIMEOUT); // Never
			setNegativeTimeout(0);

			/*
			 * First look for compressed OUI database.
			 */

			try {
				URL url = JConfig.getResourceURL(RESOURCE_COMPRESSED_OUI_DATABASE);
				if (url != null) {
					logger
					    .fine("loading compressed database file from " + url.toString());
					readOuisFromCompressedIEEEDb(RESOURCE_COMPRESSED_OUI_DATABASE);
					return;
				}

				boolean download =
				    Boolean.parseBoolean(JConfig.getProperty(PROPERTY_OUI_DB_DOWNLOAD,
				        DEFAULT_OUI_DB_DOWNLOAD));
				String u = JConfig.getProperty(PROPERTY_OUI_DB_URL);
				if (u != null && download) {
					url = new URL(u);
					logger.fine("loading remote database " + url.toString());
					loadCache(url);
					return;
				}
			} catch (IOException e) {
				logger.log(Level.WARNING, "error while reading database", e);
			}
		} else {
			super.initializeIfNeeded();
		}
	}

	/**
	 * Download IEEE supplied OUI.txt database of manufacturer prefixes and codes.
	 * The file is downloaded using the protocol specified in the URL, parsed and
	 * cached indefinately. The machine making the URL connection must have
	 * internet connection available as well as neccessary security permissions
	 * form JRE in order to make the connection.
	 * <p>
	 * 
	 * @param url
	 *          The url of the IEEE resource to load. If the url is null, the
	 *          default uri is attempted {@value #IEEE_OUI_DATABASE_PATH}.
	 * @return number of entries cached
	 * @exception IOException
	 *              any IO errors
	 */
	@Override
	public int loadCache(URL url) throws IOException {
		if (url == null) {
			url = new URL(IEEE_OUI_DATABASE_PATH);
		}
		return readOuisFromRawIEEEDb(new BufferedReader(new InputStreamReader(url
		    .openStream())));
	}

	private int readOuisFromCompressedIEEEDb(BufferedReader in)
	    throws IOException {
		int count = 0;

		try {
			String s;
			while ((s = in.readLine()) != null) {
				String[] c = s.split(":", 2);
				if (c.length < 2) {
					continue;
				}

				Long i = Long.parseLong(c[0], 16);

				super.addToCache(i, c[1]);
				count++;

			}
		} finally {
			in.close(); // Make sure we close the file
		}

		return count;
	}

	private boolean readOuisFromCompressedIEEEDb(String f)
	    throws FileNotFoundException, IOException {
		/*
		 * Try local file first, more efficient
		 */
		File file = new File(f);
		if (file.canRead()) {
			readOuisFromCompressedIEEEDb(new BufferedReader(new FileReader(file)));
			return true;
		}

		/*
		 * Otherwise look for it in classpath
		 */
		InputStream in =
		    JFormatter.class.getClassLoader().getResourceAsStream("resources/" + f);
		if (in == null) {
			return false; // Can't find it
		}
		readOuisFromCompressedIEEEDb(new BufferedReader(new InputStreamReader(in)));

		return true;
	}

	private int readOuisFromRawIEEEDb(BufferedReader in) throws IOException {
		int count = 0;
		try {
			String s;
			while ((s = in.readLine()) != null) {
				if (s.contains("(base 16)")) {
					String[] c = s.split("\t\t");
					if (c.length < 2) {
						continue;
					}

					String p = c[0].split(" ")[0];
					long i = Long.parseLong(p, 16);
					String[] a = c[1].split(" ");

					if (a.length > 1) {
						super.addToCache(i, a[1]);
						count++;
					}
				}
			}
		} finally {
			in.close(); // Make sure we close the file
		}

		return count;
	}

	/**
	 * Resolves the supplied address to a human readable name.
	 * 
	 * @return resolved name or null if not resolved
	 */
	@Override
	public String resolveToName(byte[] address, long hash) {
		return null; // If its not in the cache, we don't know what it is
	}

	/**
	 * Generates a special hashcode for first 3 bytes of the address that is
	 * unique for every address.
	 */
	@Override
	public long toHashCode(byte[] address) {
		return ((address[2] < 0) ? address[2] + 256 : address[2])
		    | ((address[1] < 0) ? address[1] + 256 : address[1]) << 8
		    | ((address[0] < 0) ? address[0] + 256 : address[0]) << 16;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.util.AbstractResolver#resolveToName(long, long)
	 */
	@Override
	protected String resolveToName(long number, long hash) {
		throw new UnsupportedOperationException(
		    "this resolver only resolves addresses in byte[] form");
	}
}