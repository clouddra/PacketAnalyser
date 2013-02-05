
/**
 *
 * @author A0072292H Chong Yun Long
 */
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashSet;
import javax.swing.JFileChooser;

class Parser {

    public int dnsCount;
    public int transCount;
    private HashSet<Integer> transactions;
    StringBuilder output;

    public static enum type {
        IP, ARP, ICMP, TCP, UDP, PING_REQUEST, PING_REPLY, DHCP_CLIENT, DHCP_SERVER, DNS
    };
    // protocol values in the different layers
    public static String[] protocol_val = {"0800", "0806", "01", "06", "11", "08", "00", "0044", "0043", "0035"};
    // various offsets
    public static int[] protocol_offset = {24, 0x0806, 0x01, 0x06, 0x11, 8, 0, 67, 53};

    public Parser() {
        dnsCount = 0;
        transCount = 0;
        output = new StringBuilder();
        transactions = new HashSet<Integer>();
    }

    static public byte[] hex2Byte(String str) {
        byte[] bytes = new byte[str.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer
                    .parseInt(str.substring(2 * i, 2 * i + 2), 16);
        }
        return bytes;
    }

    // retrieve the hex string belonging to a packet
    public String extractBytes(String packet) {
        int start, end;
        start = packet.indexOf("  ");
        end = packet.indexOf("   ");
        try {
            packet = packet.substring(start, end).replaceAll("\\s+", "");

        } catch (IndexOutOfBoundsException e) {
            packet = "";
        }
        return packet;
    }

    public void processDatalink(String frame) {
        String networkPkt = frame.substring(24);

        if (networkPkt.startsWith(protocol_val[0])) {
            networkPkt = networkPkt.substring(4);
            processIP(networkPkt);

        }
    }

    public void processIP(String packet) {
        int hlen = Character.digit(packet.charAt(1), 16) * 4;
        String protocol = packet.substring(18, 20);
        packet = packet.substring((hlen) * 2);

        if (protocol.equals(Parser.protocol_val[Parser.type.UDP.ordinal()]) || protocol.equals(Parser.protocol_val[Parser.type.TCP.ordinal()])) {
            processUDP(packet);
        }

    }

    public void processUDP(String Datagram) {
        int pointer = 0;

        String sourcePort = Datagram.substring(pointer, pointer += 4);
        String destPort = Datagram.substring(pointer, pointer += 4);
        int length = Integer.parseInt(Datagram.substring(pointer, pointer += 4), 16);

        if (destPort.equals(Parser.protocol_val[Parser.type.DNS.ordinal()]) || sourcePort.equals(Parser.protocol_val[Parser.type.DNS.ordinal()])) {
            processDNS(Datagram.substring(8 * 2));

        }
    }

    public void processDNS(String data) {
        dnsCount++;
        int offset = 0;
        int type, rclass;
        int question;
        int answer;
        int authority;
        int additional;
        int transID;
        int ttl;


        boolean isTrans = false;

        transID = Integer.parseInt(data.substring(offset, offset += 4), 16);
        String flag = data.substring(offset, offset += 4);

        if (Integer.parseInt(flag, 16) >= 32768) {
            isTrans = transactions.contains(transID);
        } else {
            transactions.add(transID);
        }

        // Only process if it is part of a transaction
        if (isTrans) {
            transCount++;

            question = Integer.parseInt(data.substring(offset, offset += 4), 16);
            answer = Integer.parseInt(data.substring(offset, offset += 4), 16);
            authority = Integer.parseInt(data.substring(offset, offset += 4), 16);
            additional = Integer.parseInt(data.substring(offset, offset += 4), 16);

            output.append("----------------------\nDNS Transaction\n----------------------\n");
            output.append("transaction_id = ").append(Integer.toHexString(transID)).append("\n");
            output.append("Questions = ").append(question).append("\n");
            output.append("Answers RR = ").append(answer).append("\n");
            output.append("Authority RRs = ").append(authority).append("\n");
            output.append("Additonal RRs = ").append(additional).append("\n");

            // process query
            for (output.append("Queries:\n"); question > 0; question--) {

                output.append("\tName = ");
                offset = processRData(offset, data);
                output.append("\n");

                type = Integer.parseInt(data.substring(offset, offset += 4), 16);
                rclass = Integer.parseInt(data.substring(offset, offset += 4), 16);

                output.append("\tType = ").append(type).append("\n");
                output.append("\tClass = ").append(rclass).append("\n");
                if (type != 1 && type != 12) {
                    output = new StringBuilder();
                    return;
                }
            }

            // process answer RR
            for (output.append("Answers:\n"); answer > 0; answer--) {
                output.append("\tName = ");
                offset = processRData(offset, data);
                output.append("\n");

                type = Integer.parseInt(data.substring(offset, offset += 4), 16);
                rclass = Integer.parseInt(data.substring(offset, offset += 4), 16);
                ttl = Integer.parseInt(data.substring(offset, offset += 8), 16);

                output.append("\tType =  ").append(type).append("\n");
                output.append("\tClass = ").append(rclass).append("\n");
                output.append("\tTime to live = ").append(ttl).append("\n");

                offset = processRData(offset, data, type);
                output.append("\n");
            }

            System.out.println(output);

        }
        output = new StringBuilder();
    }

    // processes RDATA
    private int processRData(int offset, String data, int type) {
        int len = Integer.parseInt(data.substring(offset, offset += 4), 16);
        StringBuilder rdata = new StringBuilder();

        output.append("\tData length = ").append(len).append("\n");
        switch (type) {
            // A record
            case 1:
                for (int i = 0; i < len; i++) {
                    rdata.append(Integer.parseInt(data.substring(offset, offset += 2), 16));
                    rdata.append(".");
                }
                rdata.setLength(rdata.length() - 1);
                output.append("\tAddr = ").append(rdata).append("\n");
                break;
            // CNAME record
            case 5:
                output.append("\tCNAME = ");
                processRData(offset, data);
                offset += len * 2;
                output.append("\n");
                break;
            // PTR record
            case 12:
                output.append("\tDomain Name = ");
                processRData(offset, data);
                offset += len * 2;
                output.append("\n");
                break;
            default:
                offset += len * 2;
        }

        return offset;
    }

    private int processRData(int offset, String data) {

        int pointer = calcPointerOffset(Integer.parseInt(data.substring(offset, offset + 4), 16));
        if (pointer != -1) {
            extractName(data, pointer, "Name");
            offset += 4;
        } else {
            offset = extractName(data, offset, "Name");
        }

        return offset;

    }

    // calculates pointer offset. Returns -1 if not a pointer
    private int calcPointerOffset(int offset) {
        if (offset >= 49152) {
            offset = offset - 49152;
            offset *= 2;
        } else {
            offset = -1;
        }
        return offset;
    }

    // extract hostname
    private int extractName(String data, int pointer, String field) {
        int count, newPointer;
        

        while ((count = Integer.parseInt(data.substring(pointer, pointer + 2), 16)) != 0) {
            newPointer = calcPointerOffset(Integer.parseInt(data.substring(pointer, pointer + 4), 16));
            pointer += 2;
            if (newPointer != -1) {
                extractName(data, newPointer, field);
                break;
            }

            output.append(hexToAscii(data.substring(pointer, pointer += count * 2))).append(".");

        }

        return pointer += 2;
    }

    private String hexToAscii(String s) {
        StringBuilder ascii = new StringBuilder();
        for (int i = 0; i < s.length(); i += 2) {
            String hex = "" + s.charAt(i) + s.charAt(i + 1);
            int ival = Integer.parseInt(hex, 16);
            ascii.append((char) ival);
        }
        return ascii.toString();
    }
}

public class DNSAnalyser {

    // open and read file
    public static BufferedReader setupFileStream() {
        File fileDir = null;
        BufferedReader in = null;

        JFileChooser chooser = new JFileChooser();
        chooser.setCurrentDirectory(new java.io.File("."));
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        chooser.setDialogTitle("Select hex file.");
        if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
            fileDir = chooser.getSelectedFile();

        } else {
            System.exit(0);
        }
        try {
            in = new BufferedReader(new FileReader(fileDir));
        } catch (FileNotFoundException ex) {
            System.out.println("File not found!");
            System.exit(0);
        }

        return in;
    }

    public static void main(String[] args) {

        int discard = 0;
        BufferedReader in;
        String thisline;
        String packet = "";

        Parser parse = new Parser();
        in = setupFileStream();

        // read hex file by line
        try {
            while ((thisline = in.readLine()) != null) {

                if (thisline.startsWith("00")) {
                    do {
                        packet += parse.extractBytes(thisline);
                    } while ((thisline = in.readLine()) != null && !thisline.equals(""));

                    if (discard == 0) {
                        parse.processDatalink(packet);
                    } else {
                        discard = 0;
                    }

                } else if (thisline.contains("Reassembled") || thisline.contains("Uncompressed")) {
                    discard = 1;
                }
                packet = "";

            }
        } catch (IOException e) {
            System.err.println("Error: " + e);
        }

        System.out.println("total number of DNS packets = " + parse.dnsCount);
        System.out.println("total number of DNS transactions " + parse.transCount);
    }
}
