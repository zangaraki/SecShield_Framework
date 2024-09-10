package MyProject;

import MyProject.PhysicalTopologyGenerator.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.cloudbus.cloudsim.Vm;

/**
 *
 * @author admin
 */
public class Config {

    public static String Method = "Based";// Proposed , Base
    static double Time_Flag = 5; // mS // time expiration
    public static int Packets = 100; // number of request 
    
     static int CoapServer_Number = 20; // 
    static int CoapClient_Number = 100; //

    static int redundancy = 4;	// For aggr and core tier, how many switches are connected.
    static int Allowed_Packets = 0;

    static double latency = 0.1;
    static long iops = 1000000000L;
    static int pe = 1;
    static long mips = 100;//8000;
    static int ram = 10240;
    static long storage = 10000000;
    //long bw = 125000000;
    static long bw = 250;// 100, 250
    public static int VM_group_Count = Packets / 4; // 
    public static int user = 10;
    static int fanout = 100; // Host
    static int numPods = 2;	// 

    
    public static List<CoapClientSpec> CoapClients = new ArrayList<CoapClientSpec>();
    public static List<CoapServerSpec> CoapServers = new ArrayList<CoapServerSpec>();

    public static List<List<String>> Client_Table = new ArrayList<>();
    public static List<List<String>> Server_Table = new ArrayList<>();

    static List<HostSpec> hosts = new ArrayList<HostSpec>();
    static List<SwitchSpec> switches = new ArrayList<SwitchSpec>();
    static List<LinkSpec> links = new ArrayList<LinkSpec>();
    static LRUcache TEMP=new LRUcache(100);
    static HashMap<HashMap<Integer, Integer>, Double> Last_Request_Time
            = new HashMap<>(); // VM id , Last_Request_Time  
    static String sub_att="",obj_att="";//Client attribute and server attribute that are randomly checked for access policy
    static int vmID, Source, Age, Sensivity,securityLabel;  //vmID,Client att,client att,server att
    static int ID, DOMAIN;
    static String URI = "", IP = "",Role="",Action="",Specialty="";//server att,server att,client att,action, client att
    static int Packet_Counter = 0;
    static int AC = 0;
    static int No_AC = 0;
    public static double FinishTime = 0;
    public static double startTime;
    public static double duration;
}
