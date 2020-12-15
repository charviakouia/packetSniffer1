package packetSinks;

import org.pcap4j.packet.Packet;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import packetSinks.PacketDeserializer.PacketAnalysisResults;

public class PacketDeserializationAnalysisFileOutputter extends AbstractPacketFileOutputter {

    private Map<AggregateKey, Integer> aggregateOccurances;

    public PacketDeserializationAnalysisFileOutputter(String fileName) throws IOException {
        super(fileName);
        this.aggregateOccurances = new HashMap<>();
    }

    @Override
    protected void processPacket(Packet o) {
        PacketAnalysisResults results = PacketDeserializer.analyzePacket(o);
        writer.println();
        writer.println(results);
        writer.println("---------------- END ----------------");
        updateAggregateCount(results);
    }

    private void updateAggregateCount(PacketAnalysisResults results){
        AggregateKey key = new AggregateKey(results.getType(), results.isSerializedObjectByteLengthFoundInPrefix());
        Integer numOccurances = aggregateOccurances.get(key);
        numOccurances = (numOccurances == null ? 1 : numOccurances + 1);
        aggregateOccurances.put(key, numOccurances);
    }

    @Override
    protected void doBeforeShuttingDown(){
        for (Map.Entry<AggregateKey, Integer> entry : aggregateOccurances.entrySet()){
            writer.println(entry.getKey().getString(entry.getValue()));
        }
    }

    private static class AggregateKey {

        private Class<?> deserializedObjType;
        private boolean lenFoundInPrefix;

        AggregateKey(Class<?> deserializedObjType, boolean lenFoundInPrefix){
            this.deserializedObjType = deserializedObjType;
            this.lenFoundInPrefix = lenFoundInPrefix;
        }

        @Override
        public String toString() {
            return getString(-1);
        }

        String getString(int numOccurances){
            if (numOccurances <= 0){
                return String.format("(class: %s, serial length found: %b)", (deserializedObjType == null ? null : deserializedObjType.getName()), lenFoundInPrefix);
            } else {
                return String.format("(class: %s, serial length found: %b, number of occurances: %d)", (deserializedObjType == null ? null : deserializedObjType.getName()), lenFoundInPrefix, numOccurances);
            }
        }

        @Override
        public boolean equals(Object o){
            if (this == o){
                return true;
            } else if (!(o instanceof AggregateKey)){
                return false;
            } else {
                return Objects.equals(this.deserializedObjType, ((AggregateKey) o).deserializedObjType) && Objects.equals(this.lenFoundInPrefix, ((AggregateKey) o).lenFoundInPrefix);
            }
        }

        @Override
        public int hashCode(){
            return Objects.hash(deserializedObjType, lenFoundInPrefix);
        }

    }

}
