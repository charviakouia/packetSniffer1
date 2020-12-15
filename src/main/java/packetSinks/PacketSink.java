package packetSinks;

import org.pcap4j.packet.Packet;

public interface PacketSink extends Runnable {

    void acceptPacket(Packet o);

    void incrementNumActiveSources();

    void decrementNumActiveSources();

}
