package display;

import org.pcap4j.core.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import packetSinks.PacketDeserializationAnalysisFileOutputter;
import packetSinks.PacketSink;
import packetSinks.RawPacketFileOutputter;
import sniffer.Sniffer;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.*;

public class ConsoleInterface {

    private static final Logger logger = LoggerFactory.getLogger(ConsoleInterface.class);

    private static final String RAW_PACKETS_OUTPUT_FILE_NAME = "/Users/ivancharviakou/Desktop/rawPackets.txt";
    private static final String PACKET_ANALYSIS_OUTPUT_FILE_NAME = "/Users/ivancharviakou/Desktop/packetAnalysis.txt";
    private static final String DEVICE_TO_SNIFF = "lo0"; // lo0, en0
    private static ThreadPoolExecutor pool;
    private static Sniffer sniffer;
    private static List<PacketSink> sinks;
    private static Future<?> snifferHandle;

    private ConsoleInterface(){}

    public static void main(String[] args) {
        if (!initialize()){ return; }
        Scanner console = new Scanner(System.in);
        String input;
        while (!(input = console.nextLine().toLowerCase()).equals(Command.QUITIT.toString().toLowerCase())){
            respondToInput(input);
        }
        shutdown();
    }

    private static boolean initialize() {
        try {
            sniffer = new Sniffer(DEVICE_TO_SNIFF);
            sinks = new LinkedList<>();
            pool = new ThreadPoolExecutor(3, 5, 10000, TimeUnit.MILLISECONDS, new LinkedBlockingQueue<>());
            initializeSinks();
        } catch (IOException | PcapNativeException e){
            logger.error("Something's went wrong while initializing the console interface, quitting...");
            return false;
        }
        return true;
    }

    private static void initializeSinks() throws IOException {
        sinks.add(new RawPacketFileOutputter(RAW_PACKETS_OUTPUT_FILE_NAME));
        sinks.add(new PacketDeserializationAnalysisFileOutputter(PACKET_ANALYSIS_OUTPUT_FILE_NAME));
        for (PacketSink sink : sinks){
            sniffer.addSink(sink);
            sink.incrementNumActiveSources();
            pool.execute(sink);
        }
    }

    private static void respondToInput(String input){
        if (input.equals(Command.SNIFIT.toString().toLowerCase())){
            snifit();
        } else if (input.equals(Command.STOPIT.toString().toLowerCase())){
            stopit();
        } else {
            System.out.println("Incorrectly formatted input... Try again");
        }
    }

    private static void snifit(){
        if (snifferHandle == null || snifferHandle.isDone()){
            snifferHandle = pool.submit(sniffer);
        } else {
            System.out.println("Already sniffing...");
        }
    }

    private static void stopit(){
        if (snifferHandle != null && !snifferHandle.isDone()){
            snifferHandle.cancel(true);
        } else {
            System.out.println("Already stopped...");
        }
    }

    private static void shutdown(){
        for (PacketSink sink : sinks){
            sink.decrementNumActiveSources();
        }
        pool.shutdownNow();
        logger.info("Shutdown complete - waiting on threads");
    }

    public enum Command {
        SNIFIT,
        STOPIT,
        QUITIT
    }

}
