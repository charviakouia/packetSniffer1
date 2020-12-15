package display;

import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.net.NetworkInterface;
import java.util.List;

public class NetIntConsoleDisplay {

    public static void main(String[] args) {
        try {
            List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
            for (PcapNetworkInterface interfaze: interfaces) {
                System.out.println(interfaze.toString());
            }
        } catch (PcapNativeException e){
            System.out.println("Couldn't scan for devices... Here's the error message:");
            System.out.println(e.toString());
        }
    }

}
