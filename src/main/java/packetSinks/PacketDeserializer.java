package packetSinks;

import org.apache.commons.codec.DecoderException;
import org.pcap4j.packet.Packet;
import org.apache.commons.codec.binary.Hex;

import java.io.*;
import java.util.Arrays;
import java.util.logging.Logger;

public final class PacketDeserializer {

    private static final int MAX_UNSIGNED_BYTE_VALUE = Math.toIntExact(Math.round(Math.pow(2, 8))) - 1;
    private static final int MAX_SIGNED_BYTE_VALUE = Math.toIntExact(Math.round(Math.pow(2, 7))) - 1;
    private static final int MIN_SIGNED_BYTE_VALUE = - Math.toIntExact(Math.round(Math.pow(2, 7)));

    private PacketDeserializer(){}

    public static PacketAnalysisResults analyzePacket(Packet packet){
        PacketAnalysisResults results = new PacketAnalysisResults();
        byte[] byteStream = extractByteStream(packet);
        extractObject(byteStream, results);
        results.setBytestreamAsciiTranslation(new String(byteStream));
        findLengthInPrefix(results);
        return results;
    }

    private static byte[] extractByteStream(Packet packet){
        Packet packet0 = null;
        Packet packet1 = packet;
        while (packet1 != null && !packet1.equals(packet0)){
            packet0 = packet1;
            packet1 = packet1.getPayload();
        }
        return (packet0 == null ? new byte[]{} : packet0.getRawData());
    }

    private static void extractObject(byte[] byteStream, PacketAnalysisResults result){
        ByteArrayInputStream bais = null;
        ObjectInputStream ois = null;
        Object object = null;
        boolean completedSuccessfully = false;
        int byteOffset = 0;
        int bytesLeft = 0;
        while (!completedSuccessfully && byteOffset != byteStream.length){
            try {
                bais = new ByteArrayInputStream(byteStream, byteOffset, byteStream.length - byteOffset);
                ois = new ObjectInputStream(bais);
                object = ois.readObject();
                bytesLeft = bais.available();
                completedSuccessfully = true;
            } catch (IOException | ClassNotFoundException e){
                byteOffset++;
                object = null;
            } finally {
                boolean oisClosed = true;
                if (ois != null) { try { ois.close(); } catch (IOException e){ oisClosed = false; } }
                if (bais != null && !oisClosed) { try { ois.close(); } catch (IOException ignored){} }
            }
        }
        result.setType((object == null ? null : object.getClass()));
        result.setSerializedObjectByteLength(byteStream.length - byteOffset - bytesLeft);
        result.setBytestreamPrefix(Arrays.copyOfRange(byteStream, 0, byteOffset));
        result.setBytestreamSuffix(Arrays.copyOfRange(byteStream, byteStream.length - bytesLeft, byteStream.length));
    }

    private static void findLengthInPrefix(PacketAnalysisResults result){
        byte[] prefix = result.getBytestreamPrefix();
        int length = result.getSerializedObjectByteLength();
        int numBytesForLength = Math.toIntExact(Math.round(Math.ceil(Math.log(length + 1) / Math.log(MAX_UNSIGNED_BYTE_VALUE))));
        byte[] searchPattern = new byte[numBytesForLength];
        for (int remainder = length, i = 0; remainder > 0; remainder /= MAX_UNSIGNED_BYTE_VALUE, i++){
            int numToEncode = remainder % MAX_UNSIGNED_BYTE_VALUE;
            if (numToEncode > MAX_SIGNED_BYTE_VALUE){
                numToEncode = numToEncode - MAX_SIGNED_BYTE_VALUE - 1 + MIN_SIGNED_BYTE_VALUE;
            }
            searchPattern[i] = (byte) numToEncode;
        }
        boolean match = false;
        for (int i = 0; i < prefix.length - searchPattern.length; i++){
            match = true;
            for (int j = 0; j < searchPattern.length; j++){
                if (prefix[prefix.length - 1 - j] != searchPattern[searchPattern.length - 1 - j]){
                    match = false;
                    break;
                }
            }
            if (match){ break; }
        }
        result.setSerializedObjectByteLengthFoundInPrefix(match);
    }

    static class PacketAnalysisResults {

        private Class<?> type;
        private boolean serializedObjectByteLengthFoundInPrefix;
        private int serializedObjectByteLength;

        private byte[] bytestreamPrefix;
        private byte[] bytestreamSuffix;

        private String bytestreamAsciiTranslation;

        private PacketAnalysisResults(){}

        public Class<?> getType() {
            return type;
        }

        public void setType(Class<?> type) {
            this.type = type;
        }

        public boolean isSerializedObjectByteLengthFoundInPrefix() {
            return serializedObjectByteLengthFoundInPrefix;
        }

        public void setSerializedObjectByteLengthFoundInPrefix(boolean serializedObjectByteLengthFoundInPrefix) {
            this.serializedObjectByteLengthFoundInPrefix = serializedObjectByteLengthFoundInPrefix;
        }

        public int getSerializedObjectByteLength() {
            return serializedObjectByteLength;
        }

        public void setSerializedObjectByteLength(int serializedObjectByteLength) {
            this.serializedObjectByteLength = serializedObjectByteLength;
        }

        public byte[] getBytestreamPrefix() {
            return bytestreamPrefix;
        }

        public void setBytestreamPrefix(byte[] bytestreamPrefix) {
            this.bytestreamPrefix = bytestreamPrefix;
        }

        public byte[] getBytestreamSuffix() {
            return bytestreamSuffix;
        }

        public void setBytestreamSuffix(byte[] bytestreamSuffix) {
            this.bytestreamSuffix = bytestreamSuffix;
        }

        public String getBytestreamAsciiTranslation() {
            return bytestreamAsciiTranslation;
        }

        public void setBytestreamAsciiTranslation(String bytestreamAsciiTranslation) {
            this.bytestreamAsciiTranslation = bytestreamAsciiTranslation;
        }

        @Override
        public String toString() {
            return String.format("{type: %s, length found: %b, length: %d, prefix: %s, suffix: %s, bytestream translation: %s}",
                    (type == null ? null : type.getName()), serializedObjectByteLengthFoundInPrefix, serializedObjectByteLength,
                    (bytestreamPrefix == null ? null : Hex.encodeHexString(bytestreamPrefix)),
                    (bytestreamSuffix == null ? null : Hex.encodeHexString(bytestreamSuffix)),
                    bytestreamAsciiTranslation);
        }
    }

}
