package org.jnetpcap.analysis;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public interface JPeerableAnalysis extends JAnalysis {
	
	public <T extends JPeerableAnalysis> T getAnalysis(T analysis);

	public <T extends JPeerableAnalysis> boolean hasAnalysis(T analysis);

}