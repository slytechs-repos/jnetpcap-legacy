package org.jnetpcap.bug1848662;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHandler;
import org.jnetpcap.PcapIf;

@SuppressWarnings("deprecation")
public class TestSniffer {

   public static void main(String[] args) {
      List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with
                                                      // NICs
      StringBuilder errbuf = new StringBuilder(); // For any error msgs

      /*************************************************************************
       * First get a list of devices on this system
       ************************************************************************/
      int r = Pcap.findAllDevs(alldevs, errbuf);
      if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
         System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
         return;
      }

      System.out.println("Network devices found:");

      int i = 0;
      for (PcapIf device : alldevs) {
         System.out.printf("#%d: %s [%s]\n", i++, device.getDescription(), device.getName());
      }

      PcapIf device = alldevs.get(0); // We know we have atleast 1 device
      System.out.printf("\nChoosing '%s' on your behalf:\n", device.getDescription());

      /*************************************************************************
       * Second we open up the selected device
       ************************************************************************/
      int snaplen = 64 * 1024; // Capture entire packet, no trucation
      int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
      int timeout = 10 * 1000; // 10 seconds in millis
      Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

      if (pcap == null) {
         System.err.printf("Error while opening device for capture: " + errbuf.toString());
         return;
      }

      /*************************************************************************
       * Third we create a packet hander which will be dispatched to from the
       * libpcap loop.
       ************************************************************************/
      PcapHandler<String> printSummaryHandler = new PcapHandler<String>() {

         public void nextPacket(String user, long seconds, int useconds, int caplen, int len, ByteBuffer buffer) {
            Date timestamp = new Date(seconds * 1000); // In millis

            System.out.printf("Received packet at %s caplen=%-4d len=%-4d %s\n", timestamp.toString(), caplen, // Length
                                                                                                               // actually
                                                                                                               // captured
                     len, // Original length of the packet
                     user // User supplied object
                     );
         }
      };

      /*************************************************************************
       * Fourth we enter the loop and tell it to capture 10 packets
       ************************************************************************/
      pcap.loop(10, printSummaryHandler, "jNetPcap rocks!");

      /*************************************************************************
       * Last thing to do is close the pcap handle
       ************************************************************************/
      pcap.close();
   }
}
