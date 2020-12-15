package packetSinks;

import packetSinks.PacketSink;
import org.pcap4j.packet.Packet;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

public class RawPacketFileOutputter extends AbstractPacketFileOutputter {

    public RawPacketFileOutputter(String fileName) throws IOException {
        super(fileName);
    }

    @Override
    protected void processPacket(Packet o) {
        writer.println(o.toString());
        writer.println("--- END OF PACKET ---");
        writer.println();
    }

}
