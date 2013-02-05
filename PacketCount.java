/**
 *
 * @author A0072292H Chong Yun Long
 */

import java.io.*;
import javax.swing.JFileChooser;

class Parser {
    public int ipCount;
    public int arpCount;
    public int tcpCount;
    public int udpCount;
    public int icmpCount;
    public int dhcpCount;
    public int dnsCount;
    public int pingCount;

    public static enum type {

        IP, ARP, ICMP, TCP, UDP, PING_REQUEST, PING_REPLY, DHCP_CLIENT, DHCP_SERVER, DNS
    };
    
    // protocol values in the different layers
    public static String[] protocol_val = {"0800", "0806", "01", "06", "11", "08", "00", "0044", "0043", "0035"};
    
    // various offsets
    public static int[] protocol_offset = {24, 0x0806, 0x01, 0x06, 0x11, 8, 0, 67, 53};

    public Parser() {
        ipCount = 0;
        arpCount = 0;
        tcpCount = 0;
        udpCount = 0;
        icmpCount = 0;
        dhcpCount = 0;
        dnsCount = 0;
        pingCount = 0;
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
    
    // data link layer processing
    public void processDatalink(String frame) {
        String networkPkt = frame.substring(24);

        if (networkPkt.startsWith(protocol_val[0])) {
            networkPkt = networkPkt.substring(4);
            processIP(networkPkt);

        } else if (networkPkt.startsWith(protocol_val[1])) {
            arpCount++;
        }
    }

    // IP processing
    public void processIP(String packet) {
        ipCount++;
        int hlen = Character.digit(packet.charAt(1), 16) * 4;
        String protocol = packet.substring(18, 20);
        packet = packet.substring((hlen) * 2);

        if (protocol.equals(Parser.protocol_val[Parser.type.UDP.ordinal()])) {
            processUDP(packet);
        } else if (protocol.equals(Parser.protocol_val[Parser.type.TCP.ordinal()])) {
            processTCP(packet);
        } else if (protocol.equals(Parser.protocol_val[Parser.type.ICMP.ordinal()])) {
            processICMP(packet);
        }

    }
    
    // UDP processing
    public void processUDP(String Datagram) {
        int pointer = 0;
        udpCount++;
       
        String sourcePort = Datagram.substring(pointer, pointer += 4);
        String destPort = Datagram.substring(pointer, pointer += 4);
        if (sourcePort.equals(Parser.protocol_val[Parser.type.DHCP_CLIENT.ordinal()]) || sourcePort.equals(Parser.protocol_val[Parser.type.DHCP_SERVER.ordinal()])) {
            dhcpCount++;
        }
        if (destPort.equals(Parser.protocol_val[Parser.type.DNS.ordinal()]) || sourcePort.equals(Parser.protocol_val[Parser.type.DNS.ordinal()])) {
            dnsCount++;
        }
    }

    // ICMP processing
    public void processICMP(String Datagram) {
        icmpCount++;
        String type = Datagram.substring(0, 2);
        if (type.equals(Parser.protocol_val[Parser.type.PING_REPLY.ordinal()]) || type.equals(Parser.protocol_val[Parser.type.PING_REQUEST.ordinal()])) {
            pingCount++;
        }
    }

    public void processTCP(String Datagram) {
        tcpCount++;
    }
}

public class PacketCount {

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
        System.out.println("total number of Ethernet (IP + ARP) packets = " + (parse.arpCount + parse.ipCount)) ;
        System.out.println("total number of IP packets " + parse.ipCount);
        System.out.println("total number of ARP packets " + parse.arpCount);        
        System.out.println("total number of ICMP packets " + parse.icmpCount);
        System.out.println("total number of TCP packets " + parse.tcpCount);
        System.out.println("total number of UDP packets " + parse.udpCount);
        System.out.println("total number of Ping packets " + parse.pingCount);
        System.out.println("total number of DHCP packets " + parse.dhcpCount);
        System.out.println("total number of DNS packets " + parse.dnsCount);


    }
}
