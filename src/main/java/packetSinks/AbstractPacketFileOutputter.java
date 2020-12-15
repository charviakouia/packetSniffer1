package packetSinks;

import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sniffer.Sniffer;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public abstract class AbstractPacketFileOutputter implements PacketSink, Runnable {

    private static final Logger logger = LoggerFactory.getLogger(AbstractPacketFileOutputter.class);

    protected PrintWriter writer;
    private int numSources;
    private boolean shuttingDown;

    private BlockingQueue<Packet> packetQueue;

    public AbstractPacketFileOutputter(String fileName) throws IOException {
        this.writer = new PrintWriter(new FileWriter(fileName));
        this.numSources = 0;
        this.shuttingDown = false;
        this.packetQueue = new LinkedBlockingQueue<>();
    }

    @Override
    public void run(){
        while (packetsExpected()){
            try {
                Packet packet = packetQueue.take();
                processPacket(packet);
            } catch (InterruptedException e){
                Thread.currentThread().interrupt();
            } finally {
                if (Thread.currentThread().isInterrupted() && !isShuttingDown()){ shutdown(); }
            }
        }
    }

    private synchronized boolean isShuttingDown(){
        return shuttingDown;
    }

    private synchronized boolean packetsExpected(){
        return numSources > 0 || !shuttingDown;
    }

    @Override
    public final void acceptPacket(Packet o){
        if (packetQueue.remainingCapacity() > 0){
            packetQueue.offer(o);
        } else {
            logger.info("Couldn't save a sniffed packet - queue is too full");
        }
    }

    protected abstract void processPacket(Packet o);

    @Override
    public final synchronized void incrementNumActiveSources() {
        if (!shuttingDown){
            numSources++;
        } else {
            throw new IllegalStateException("Shutting down file outputter - cannot accept new sources");
        }
    }

    @Override
    public final synchronized void decrementNumActiveSources() {
        numSources--;
        if (shuttingDown && numSources == 0){
            doBeforeShuttingDown();
            writer.close();
        }
    }

    private synchronized void shutdown() {
        shuttingDown = true;
        if (numSources == 0){
            doBeforeShuttingDown();
            writer.close();
        }
        logger.info("A file sink has shut down");
    }

    protected void doBeforeShuttingDown(){}

}
