package sniffer;

import packetSinks.PacketSink;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.Inet4Address;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class Sniffer implements Runnable, PacketListener {

    private static final Logger logger = LoggerFactory.getLogger(Sniffer.class);

    private List<PacketSink> enabledSinks;
    private List<PacketSink> disabledSinks;
    private PcapNetworkInterface device;
    private PcapHandle sniffHandle;

    private volatile boolean workerThreadFailed;
    private LoopExecutor loopExecutor;

    private String nextFilterExpression;
    private Inet4Address nextFilterAddress;
    private boolean filterChanged;

    private BlockingQueue<Packet> packetQueue;

    public Sniffer(String deviceName) throws PcapNativeException {
        this.enabledSinks = new LinkedList<>();
        this.disabledSinks = new LinkedList<>();
        this.packetQueue = new LinkedBlockingQueue<>();
        this.device = Pcaps.getDevByName(deviceName);
        this.filterChanged = false;
        this.loopExecutor = new LoopExecutor();
    }

    @Override
    public void run() {
        initializeSniffSession();
        mainSniffSessionLoop();
        if (!workerThreadFailed){ endSniffSession(); }
    }

    private void initializeSniffSession() {
        try {
            sniffHandle = device.openLive(65535, PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS, 30000);
            if (filterChanged){ applyFilter(); }
            enableAllSinks();
            workerThreadFailed = false;
            (new Thread(loopExecutor.setParentThread(Thread.currentThread()))).start();
        } catch (PcapNativeException | NotOpenException e){
            logger.error("Something appears to be wrong with the device initialization...");
        }
    }

    private void mainSniffSessionLoop() {
        try {
            while (!Thread.currentThread().isInterrupted()) {
                Packet packet = packetQueue.take();
                notifySinks(packet);
            }
        } catch (InterruptedException e){
            Thread.currentThread().interrupt();
        } finally {
            if (workerThreadFailed){
                logger.error("The sniffer's worker thread encountered an error...");
            }
        }
    }

    private void endSniffSession(){
        logger.info("This sniffer is quitting...");
        try { sniffHandle.breakLoop(); } catch (NotOpenException ignored) {}
        disableAllSinks();
    }

    public void setFilterForNextSniff(String filterExpression, Inet4Address mask){
        this.nextFilterExpression = filterExpression;
        this.nextFilterAddress = mask;
        filterChanged = true;
    }

    private void applyFilter() throws PcapNativeException, NotOpenException {
        BpfProgram filter = sniffHandle.compileFilter(nextFilterExpression, BpfProgram.BpfCompileMode.OPTIMIZE, nextFilterAddress);
        sniffHandle.setFilter(filter);
        filterChanged = false;
    }

    private synchronized void notifySinks(Packet packet){
        for (PacketSink sink : enabledSinks) {
            sink.acceptPacket(packet);
        }
    }

    private synchronized void enableAllSinks(){
        while (!disabledSinks.isEmpty()){
            PacketSink sink = disabledSinks.remove(0);
            sink.incrementNumActiveSources();
            enabledSinks.add(sink);
        }
    }

    private synchronized void disableAllSinks(){
        while (!enabledSinks.isEmpty()){
            PacketSink sink = enabledSinks.remove(0);
            sink.decrementNumActiveSources();
            disabledSinks.add(sink);
        }
    }

    public synchronized void addSink(PacketSink sink){
        disabledSinks.add(sink);
    }

    @Override
    public void gotPacket(Packet packet) {
        if (packetQueue.remainingCapacity() > 0) {
            packetQueue.offer(packet);
        } else {
            logger.info("Couldn't save a sniffed packet - queue is too full");
        }
    }

    private class LoopExecutor implements Runnable {

        private Thread parentThread;

        LoopExecutor setParentThread(Thread parentThread){
            this.parentThread = parentThread;
            return this;
        }

        @Override
        public void run() {
            try {
                sniffHandle.loop(-1, Sniffer.this);
            } catch (PcapNativeException | InterruptedException | NotOpenException e) {
                workerThreadFailed = true;
                parentThread.interrupt();
            }
        }

    }

}
