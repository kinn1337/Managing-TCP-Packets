/* Example skeleton program for CS352 Wireshark 1 assignment
 **
 ** Reads a file call input.pcap and prints the first 5
 ** packets
 **
 ** pcap4j takes an PacketListener object as input and runs
 ** a method on every packet.
 **
 ** See the PacketListener class and its gotPacket method below.
 **
 ** (c) 2021, R. P. Martin, released under the GPL version 2
 **
 **/

package tcp;

import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.*;
import org.pcap4j.packet.IpV4Packet;

// this is the main class
// see the pom.xml
public class App
{
    private static String[][] list = new String[1][9];
    static int length;
    static int total_bytes;
    static int Other_count;
    static double Other_size;
    static int UDP_count;
    static double UDP_size;
    static int ICMP_count;
    static double ICMP_size;
    static double first_time = 0;
    static double last_time = 0;
    public static void main( String[] args )
    {
        final PcapHandle handle;
        try {
            handle = Pcaps.openOffline(args[0]);
        } catch (Exception e){
            System.out.println( "opening pcap file failed!" );
            e.printStackTrace();
            return;
        }

        //this is the function that is given to the
        //loop handler and is called per packet
        PacketListener listener = new PacketListener() {
            public void gotPacket(Packet packet) {
                double size = packet.length();
                first_time = (double)handle.getTimestamp().getTime();
                last_time = (double)handle.getTimestamp().getTime();
                total_bytes += packet.getPayload().length();
                if(packet.get(TcpPacket.class) != null){
                    if(list.length == length) grow();
                    TcpPacket tcp = packet.get(TcpPacket.class);
                    String Source_IP = packet.get(IpV4Packet.class).getHeader().getSrcAddr().toString();
                    String Dst_IP = packet.get(IpV4Packet.class).getHeader().getDstAddr().toString();
                    String Source_Port = tcp.getHeader().getSrcPort().valueAsString();
                    String Dst_Port = tcp.getHeader().getDstPort().valueAsString();
                    int foundPacket = flowCheck(Source_IP, Source_Port, Dst_IP, Dst_Port);
                    if(tcp.getHeader().getFin()){
                        if(foundPacket == -1){
                            String[] arr = new String[9];
                            arr[0] = Source_IP;
                            arr[1] = Source_Port;
                            arr[2] = Dst_IP;
                            arr[3] = Dst_Port;
                            arr[4] = String.valueOf(0);
                            arr[5] = String.valueOf(1);
                            arr[6] = String.valueOf(size);
                            arr[7] = String.valueOf(first_time);
                            arr[8] = "Fin";
                            System.arraycopy(arr, 0, list[length], 0, 9);
                            length++;
                        }else{
                            if(list[foundPacket][8].equals("Syn")){
                                list[foundPacket][8] = "closed";
                                list[foundPacket][4] = String.valueOf(Integer.parseInt(list[foundPacket][4]) + Integer.parseInt(list[foundPacket][5]) + 1);
                                list[foundPacket][5] = String.valueOf(0);
                                list[foundPacket][6] = String.valueOf(Double.parseDouble(list[foundPacket][6]) + size);
                                double bytes = (Double.parseDouble(list[foundPacket][6]) * 8)/ 1000000;
                                double seconds = (double)handle.getTimestamp().getTime() - Double.parseDouble(list[foundPacket][7]);
                                seconds = seconds/1000000;
                                list[foundPacket][7] = String.valueOf(bytes/seconds);
                            }else{
                                list[foundPacket][5] = String.valueOf(Integer.parseInt(list[foundPacket][5]) + 1);
                                list[foundPacket][6] = String.valueOf(Double.parseDouble(list[foundPacket][6]) + size);
                            }

                        }
                    }else if(tcp.getHeader().getSyn()){
                        String[] arr = new String[9];
                        arr[0] = Source_IP;
                        arr[1] = Source_Port;
                        arr[2] = Dst_IP;
                        arr[3] = Dst_Port;
                        arr[4] = String.valueOf(0);
                        arr[5] = String.valueOf(1);
                        arr[6] = String.valueOf(size);
                        arr[7] = String.valueOf(first_time);
                        arr[8] = "Syn";
                        System.arraycopy(arr, 0, list[length], 0, 9);
                        length++;
                    }else{
                        if(foundPacket == -1){
                            String[] arr = new String[9];
                            arr[0] = Source_IP;
                            arr[1] = Source_Port;
                            arr[2] = Dst_IP;
                            arr[3] = Dst_Port;
                            arr[4] = String.valueOf(0);
                            arr[5] = String.valueOf(1);
                            arr[6] = String.valueOf(size);
                            arr[7] = String.valueOf(first_time);
                            arr[8] = " ";
                            System.arraycopy(arr, 0, list[length], 0, 9);
                            length++;
                        }else{
                            list[foundPacket][5] = String.valueOf(Integer.parseInt(list[foundPacket][5]) + 1);
                            list[foundPacket][6] = String.valueOf(Double.parseDouble(list[foundPacket][6]) + size);
                        }
                    }



                }else if(packet.get(UdpPacket.class) != null){
                    UDP_count++;
                    UDP_size += size;
                }else if(packet.get(IcmpV4CommonPacket.class) != null){
                    ICMP_count++;
                    ICMP_size += size;

                }else{
                    Other_count++;
                    Other_size += size;
                }

            }
        };
        try {
            int maxPackets = -1;
            // call the packet listener on the first 5 packets
            handle.loop(maxPackets, listener);
            System.out.println("TCP Summary Table");
            for(int i = 0; i < length; i++){
                for(int j = 0; j < 6; j++){
                    if(j == 0 || j == 2) System.out.print(list[i][j].substring(1) + ", ");
                    else if(j == 5) System.out.print(list[i][j]);
                    else System.out.print(list[i][j] + ", ");
                }
                for(int k = 6; k < 8; k++){
                    if(list[i][8].equals("closed") && k != 7) System.out.print(", " + list[i][k] + ", ");
                    else if(list[i][8].equals("closed") && k == 7) System.out.print(list[i][k]);

                }
                System.out.println();
            }
            System.out.println();
            System.out.println("Additional Protcols Summary Table");
            System.out.println("UDP, " + UDP_count + ", " + UDP_size);
            System.out.println("ICMP, " + ICMP_count + ", " + ICMP_size);
            System.out.println("Other, " + Other_count + ", " + Other_size);



        } catch (Exception e) {
            System.out.println( "Error Processing pcap file!" );
            e.printStackTrace();
            return;
        }
        // Cleanup when complete
        handle.close();

    }


    private static int flowCheck(String Source_IP, String Source_Port, String Dst_IP, String Dst_Port){
        for(int i = 0; i < length; i++){
            if(list[i][0].equals(Source_IP) && list[i][1].equals(Source_Port) && list[i][2].equals(Dst_IP) && list[i][3].equals(Dst_Port)) return i;
        }
        return -1;
    }

    private static void grow(){
        String[][] temp = new String[length+4][9];
        for(int i = 0; i < length; i++)
            System.arraycopy(list[i], 0, temp[i], 0, 9);
        list = temp;
    }
}
