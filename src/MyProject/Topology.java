///*
// * Title:        CloudSimSDN
// * Description:  SDN extension for CloudSim
// * Licence:      GPL - http://www.gnu.org/copyleft/gpl.html
// *
// * Copyright (c) 2015, The University of Melbourne, Australia
// */
//package MyProject;
//
//
//import it.unipr.netsec.mjcoap.coap.client.CoapClient;
//import it.unipr.netsec.mjcoap.coap.client.CoapResponseHandler;
//import it.unipr.netsec.mjcoap.coap.message.CoapRequest;
//import it.unipr.netsec.mjcoap.coap.message.CoapRequestMethod;
//import it.unipr.netsec.mjcoap.coap.message.CoapResponse;
//import it.unipr.netsec.mjcoap.coap.provider.CoapProvider;
//import it.unipr.netsec.mjcoap.coap.provider.CoapURI;
//import it.unipr.netsec.mjcoap.coap.server.CoapResource;
//import it.unipr.netsec.mjcoap.coap.server.CoapServer;
//import java.io.FileWriter;
//import java.io.IOException;
//import java.net.SocketException;
//import java.net.URISyntaxException;
//import java.util.ArrayList;
//import java.util.HashSet;
//import java.util.List;
//import java.util.Map;
//import java.util.Objects;
//import java.util.logging.Level;
//import java.util.logging.Logger;
//import org.cloudbus.cloudsim.sdn.physicalcomponents.Node;
//import org.json.simple.JSONArray;
//import org.json.simple.JSONObject;
//import org.zoolu.util.ByteUtils;
//import org.zoolu.util.SystemUtils;
//
///**
// * Generate Physical topology Json file, for example: { "nodes" : [ { "name":
// * "core", "type" : "core", "iops" : 1000000000, "bw" : 1000000000, }, { "name":
// * "edge1", "type" : "edge", "iops" : 1000000000, "bw" : 1000000000, }, {
// * "name": "host01", "type" : "host", "pes" : 1, "mips" : 30000000, "ram" :
// * 10240, "storage" : 10000000, "bw" : 200000000, }, { "name": "host02", "type"
// * : "host", "pes" : 1, "mips" : 30000000, "ram" : 10240, "storage" : 10000000,
// * "bw" : 200000000, }, ], "links" : [ { "source" : "core" , "destination" :
// * "edge1" , "latency" : 0.5 }, { "source" : "edge1" , "destination" : "host01"
// * , "latency" : 0.5 }, { "source" : "edge1" , "destination" : "host02" ,
// * "latency" : 0.5 }, ] }
// *
// * @author Jungmin Son
// * @since CloudSimSDN 1.0
// */
//public class Topology {
//
//    public static void main(String[] argv) throws SocketException, URISyntaxException, Exception {
//        startTest();
//    }
//
//    public static void startTest() throws SocketException, URISyntaxException, Exception {
//        int check = 0;
//        String jsonFileName = "physical.test.json";
//
//        PhysicalTopologyGenerator reqg = new PhysicalTopologyGenerator();
//        HostSpec hostSpec = reqg.createHostSpec(Config.pe, Config.mips, Config.ram,
//                Config.storage, Config.bw);
//        reqg.createTestTopology(hostSpec, Config.iops,
//                Config.bw, Config.bw, Config.bw,
//                Config.latency, Config.fanout, Config.numPods,
//                Config.redundancy);
//        //reqg.createTopologyFatTree(hostSpec, iops, bw, numPods, latency);
//        reqg.wrtieJSON(jsonFileName);
//    }
//
//    protected void createTestTopology(HostSpec hostSpec, long swIops,
//            long coreBw, long aggrBw, long edgeBw,
//            double latency, int fanout, int numPods, int redundancy) throws SocketException, URISyntaxException, Exception {
//        // core, aggregation, edge
//        // Core switch       
//
//        //  addCoapServer();
//        
//        SwitchSpec[] s1 = new SwitchSpec[redundancy];
//        for (int i = 0; i < redundancy; i++) {
//            s1[i] = addSwitch("sw_" + i, "core", coreBw, swIops);
//            System.out.println("Add switch " + i);
//        }
//        
//               
////        SwitchSpec[] s2 = new SwitchSpec[redundancy];
////        for (int i = 0; i < redundancy; i++) {
////            s2[i] = addSwitch("sw_" + i, "core", coreBw, swIops);
////            System.out.println("Add switch " + i);
////        }
////        
////        for (int i = 0; i < s1.length; i++) {
////            for (int j = 0; j < s2.length; j++) {
////                addLink(s1[i], s2[j], latency);
////                System.out.println("Add link between switch 1 (" + i + ") and switch 2 (" + j + ")");
////            }
////        }        
//
//        
////         for (int j = 0; j < fanout; j++) {
////                String hostname = "h" + pod + "_" + j;
////                h[j] = addHost(hostname, hostSpec);
////                System.out.println("Add Host " + j);
////                addLink(Config.CoapServers.get(pod), h[j], latency);
////            }
//        HostSpec[] h = new HostSpec[fanout];
//        for (int pod = 0; pod < Config.CoapServer_Number; pod++) {
//            //SwitchSpec e = addSwitch("e" + pod, "edge", edgeBw, swIops);
//            addCoapServer("cs_" + pod, "core", coreBw, swIops);
//            // Add link between aggr - edge
//            for (int j = 0; j < redundancy; j++) {
//                addLink(s1[j], Config.CoapServers.get(pod), latency);
//                System.out.println("Add link between edge " + pod + " and switch " + j);
//
//            }
//
//            for (int j = 0; j < fanout; j++) {
//                String hostname = "h" + pod + "_" + j;
//                h[j] = addHost(hostname, hostSpec);
//                System.out.println("Add Host " + j);
//                addLink(Config.CoapServers.get(pod), h[j], latency);
//            }
//        }
//
//   //     CoapTerminate();
//    }
//
//    protected void createTopologyFatTree(HostSpec hostSpec, long swIops, long swBw, int numpods, double latency) {
//        SwitchSpec[][] c = new SwitchSpec[numpods / 2][numpods / 2];
//        for (int i = 0; i < numpods / 2; i++) {
//            for (int j = 0; j < numpods / 2; j++) {
//                c[i][j] = addSwitch("c_" + i + "_" + j, "core", swBw, swIops);
//            }
//        }
//
//        for (int k = 0; k < numpods; k++) {
//            SwitchSpec[] e = new SwitchSpec[numpods / 2];
//            SwitchSpec[] a = new SwitchSpec[numpods / 2];
//
//            for (int i = 0; i < numpods / 2; i++) {
//                e[i] = addSwitch("e_" + k + "_" + i, "edge", swBw, swIops);
//                a[i] = addSwitch("a_" + k + "_" + i, "aggregate", swBw, swIops);
//                addLink(a[i], e[i], latency);
//
//                for (int j = 0; j < i; j++) {
//                    addLink(a[i], e[j], latency);
//                    addLink(a[j], e[i], latency);
//                }
//
//                for (int j = 0; j < numpods / 2; j++) {
//                    addLink(a[i], c[i][j], latency);
//                }
//
//                for (int j = 0; j < numpods / 2; j++) {
//                    String hostname = "h_" + k + "_" + i + "_" + j;
//                    HostSpec h = addHost(hostname, hostSpec);
//                    addLink(e[i], h, latency);
//                }
//            }
//        }
//    }
//
//    public HostSpec addHost(String name, HostSpec spec) {
//        HostSpec host = new HostSpec(spec.pe, spec.mips, spec.ram, spec.storage, spec.bw);
//
//        host.name = name;
//        host.type = "host";
//
//        Config.hosts.add(host);
//        return host;
//    }
//
//    public HostSpec addHost(String name, int pes, long mips, int ram, long storage, long bw) {
//        HostSpec host = new HostSpec(pes, mips, ram, storage, bw);
//        return addHost(name, host);
//    }
//
//    public SwitchSpec addSwitch(String name, String type, long bw, long iops) {
//        SwitchSpec sw = new SwitchSpec();
//
//        sw.name = name;
//        sw.type = type;		// core, aggregation, edge
//        sw.bw = bw;
//        sw.iops = iops;
//
//        Config.switches.add(sw);
//        return sw;
//    }
//
//    public CoapServerSpec addCoapServer(String name, String type, long bw, long iops) throws SocketException, Exception {
//        CoapServerSpec cs = new CoapServerSpec();
//
//        cs.name = name;
//        cs.type = type;		// core, aggregation, edge
//        cs.bw = bw;
//        cs.iops = iops;
//
//        Config.CoapServers.add(cs);
//        return cs;
//    }
//
//    public CoapClientSpec addCoapClient(String name, String type, long bw, long iops) throws URISyntaxException, SocketException {
//        CoapClientSpec cc = new CoapClientSpec();
//
//        cc.name = name;
//        cc.type = type;		// core, aggregation, edge
//        cc.bw = bw;
//        cc.iops = iops;
//
//        Config.CoapClients.add(cc);
//        return cc;
//    }
//
//    private void addLink(NodeSpec source, NodeSpec dest, double latency) {
//        Config.links.add(new LinkSpec(source.name, dest.name, latency));
//    }
//
//    public HostSpec createHostSpec(int pe, long mips, int ram, long storage, long bw) {
//        return new HostSpec(pe, mips, ram, storage, bw);
//    }
//
//    class NodeSpec {
//
//        String name;
//        String type;
//        long bw;
//        
//        int id;
//
//        public NodeSpec() {
//            
//           
//        }
//    }
//
//    public class HostSpec extends NodeSpec {
//
//        int pe;
//        long mips;
//        int ram;
//        long storage;
//
//        @SuppressWarnings("unchecked")
//        JSONObject toJSON() {
//            HostSpec o = this;
//            JSONObject obj = new JSONObject();
//            obj.put("name", o.name);
//            obj.put("type", o.type);
//            obj.put("storage", o.storage);
//            obj.put("pes", o.pe);
//            obj.put("mips", o.mips);
//            obj.put("ram", new Integer(o.ram));
//            obj.put("bw", o.bw);
//            return obj;
//        }
//
//        public HostSpec(int pe, long mips, int ram, long storage, long bw) {
//            this.pe = pe;
//            this.mips = mips;
//            this.ram = ram;
//            this.storage = storage;
//            this.bw = bw;
//            this.type = "host";
//
//        }
//    }
//
//    class SwitchSpec extends NodeSpec {
//
//        long iops;
//
//        @SuppressWarnings("unchecked")
//        JSONObject toJSON() {
//            SwitchSpec o = this;
//            JSONObject obj = new JSONObject();
//            obj.put("name", o.name);
//            obj.put("type", o.type);
//            obj.put("iops", o.iops);
//            obj.put("bw", o.bw);
//            return obj;
//        }
//    }
//
//    class CoapServerSpec extends NodeSpec {
//
//        long iops;
//
//        @SuppressWarnings("unchecked")
//        JSONObject toJSON() {
//            CoapServerSpec o = this;
//            JSONObject obj = new JSONObject();
//            obj.put("name", o.name);
//            obj.put("type", o.type);
//            obj.put("iops", o.iops);
//            obj.put("bw", o.bw);
//            return obj;
//        }
//
//        CoapServer server;
//
//        public CoapServerSpec() throws SocketException, Exception {
//            int local_port = CoapProvider.DYNAMIC_PORT;
//           // server= new CoapServer(local_port);
//            HashSet<CoapResource> resources = new HashSet<CoapResource>();
//            String[] resource_tuple = {"00248", "02468", "02468", ""};
////            while (resource_tuple != null) {
////                String resource_name = resource_tuple[0];
////                int resource_format = CoapResource.getContentFormatIdentifier(resource_tuple[1]);
////                String str = resource_tuple[2];
////                byte[] resource_value = str.startsWith("0x") ? ByteUtils.hexToBytes(str) : str.getBytes();
////                CoapResource res = new CoapResource(resource_name, resource_format, resource_value);
////                resources.add(res);
////                System.out.println("Adding server resource: " + res);
////            }
//
//            String resource_name = resource_tuple[0];
//            int resource_format = CoapResource.getContentFormatIdentifier(resource_tuple[1]);
//            String str = resource_tuple[2];
//            byte[] resource_value = str.startsWith("0x") ? ByteUtils.hexToBytes(str) : str.getBytes();
//
//            CoapResource res = new CoapResource(resource_name, resource_format, resource_value);
//            resources.add(res);
//            
//            // System.out.println("Adding server resource: " + res);
//
//            server = new CoapServer(local_port);
//            
//            System.out.println("Coap server local_port: " + local_port);
//            //server.getResourceValue(resource_name)
//            //System.out.println("CoAP server running on port: " + local_port);
//
//            server.halt();
//        }
//
//        public void HaltCoap() {
//            server.halt();
//        }
//    }
//
//    class CoapClientSpec extends NodeSpec {
//
//        long iops;
//
//        @SuppressWarnings("unchecked")
//        JSONObject toJSON() {
//            CoapClientSpec o = this;
//            JSONObject obj = new JSONObject();
//            obj.put("name", o.name);
//            obj.put("type", o.type);
//            obj.put("iops", o.iops);
//            obj.put("bw", o.bw);
//            return obj;
//        }
//
//        CoapClient client;
//
//        public CoapClientSpec() throws URISyntaxException, SocketException {
//            int local_port = CoapProvider.DYNAMIC_PORT;
//            client = new CoapClient(local_port);
//
//            // handler for receiving the response
//            CoapResponseHandler resp_handler = new CoapResponseHandler() {
//                @Override
//                public void onResponse(CoapRequest req, CoapResponse resp) {
//                    byte[] value = resp.getPayload();
//
////                    if (Config.Cryptography.endsWith("RSA")) {
////                        try {
////                            byte[] cipherText = do_RSAEncryption(value.toString(),
////                                    keypair_RSA.getPrivate());
////                            client.setCoapMessage(true, "RSA");
////                        } catch (Exception ex) {
////                            Logger.getLogger(NetworkOperatingSystem.class.getName()).log(Level.SEVERE, null, ex);
////                        }
////                    } else if (Config.Cryptography.endsWith("RSA-AES")) {
////                        try {
////                            // Encrypt our data with AES key
////                            String encryptedText = encryptTextUsingAES(value.toString(),
////                                    secretAESKeyString);
////
////                            // Encrypt AES Key with RSA Private Key
////                            Config.CoapClients.get(Config.CoapClients.size() - 1).encryptedAESKeyString
////                                    = encryptAESKey(secretAESKeyString,
////                                            privateKey_RSA_AES);
////                            client.setCoapMessage(true, "RSA-AES");
////
////                        } catch (Exception ex) {
////                            Logger.getLogger(NetworkOperatingSystem.class.getName()).log(Level.SEVERE, null, ex);
////                        }
////                    }
//
//                    String format = CoapResource.getContentFormat(resp.getContentFormat());
//                    System.out.println("Response: " + resp.getResponseCode() + ": " + (format != null ? format + ": " : "") + (value != null ? new String(value) : "void"));
//                    if (!req.hasObserveRegister()) {
//                        client.halt();
//                        System.exit(0);
//                    }
//                }
//
//                @Override
//                public void onRequestFailure(CoapRequest req) {
//                    if (req.hasObserveRegister()) {
//                        System.out.println("Observation finished");
//                    } else {
//                        System.out.println("Request failure");
//                    }
//                    client.halt();
//                    System.exit(0);
//                    System.out.println("2....");
//                }
//            };
//            // request                
//            String method_name = "OBSERVE";
//            //   CoapMessage m = new CoapMessage("110xff".getBytes());
//            //   CoapRequest cr = new CoapRequest(m);
//            //String resource_uri = cr.getRequestUriPath();//"coap://127.0.0.1/test";
//            //String[] resource_tuple = flags.getStringTuple("-b", 2, "<format> <value>", null, "resource value in PUT or POST requests; format can be: NULL|TEXT|XML|JSON; value can be ASCII or HEX (0x..)");
////            String resource_uri = "coap://coap.me";
////            String[] resource_tuple = {"00248", "02468"};
////            int resource_format = resource_tuple != null ? CoapResource.getContentFormatIdentifier(resource_tuple[0]) : -1;
////            byte[] resource_value = resource_tuple != null ? (resource_tuple[1].startsWith("0x") ? ByteUtils.hexToBytes(resource_tuple[1]) : resource_tuple[1].getBytes()) : null;
////
////            if (method_name.equalsIgnoreCase("OBSERVE")) { // method (e.g. GET, PUT, etc.)
////                // resource observation
////                System.out.println("1....");
////                CoapURI uri = new CoapURI(resource_uri);
////                client.observe(uri, resp_handler);
////                SystemUtils.readLine();
////                client.observeCancel(uri);
////            } else {
////                // resource GET, PUT, POST, or DELETE
////                client.request(CoapRequestMethod.getMethodByName(method_name),
////                        new CoapURI(resource_uri), resource_format, resource_value, resp_handler);
////                
////            }
////            System.out.println("3....");
////
////            client.halt();
//        }
//
//        public void HaltCoap() {
//            client.halt();
//        }
//
//    }
//
//    class LinkSpec {
//
//        String source;
//        String destination;
//        double latency;
//
//        public LinkSpec(String source, String destination, double latency2) {
//            this.source = source;
//            this.destination = destination;
//            this.latency = latency2;
//        }
//
//        @SuppressWarnings("unchecked")
//        JSONObject toJSON() {
//            LinkSpec link = this;
//            JSONObject obj = new JSONObject();
//            obj.put("source", link.source);
//            obj.put("destination", link.destination);
//            obj.put("latency", link.latency);
//            return obj;
//        }
//    }
//
//    int vmId = 0;
//
//    @SuppressWarnings("unchecked")
//    public void wrtieJSON(String jsonFileName) {
//        JSONObject obj = new JSONObject();
//
//        JSONArray nodeList = new JSONArray();
//        JSONArray linkList = new JSONArray();
//
//        for (HostSpec o : Config.hosts) {
//            nodeList.add(o.toJSON());
//        }
//        for (SwitchSpec o : Config.switches) {
//            nodeList.add(o.toJSON());
//        }
//
//        for (CoapServerSpec o : Config.CoapServers) {
//            nodeList.add(o.toJSON());
//        }
//
//        for (CoapClientSpec o : Config.CoapClients) {
//            nodeList.add(o.toJSON());
//        }
//
//        for (LinkSpec link : Config.links) {
//            linkList.add(link.toJSON());
//        }
//
//        obj.put("nodes", nodeList);
//        obj.put("links", linkList);
//
//        try {
//
//            FileWriter file = new FileWriter(jsonFileName);
//            file.write(obj.toJSONString().replaceAll(",", ",\n"));
//            file.flush();
//            file.close();
//
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//
//        System.out.println(obj);
//    }
//
//    public static void startConst() {
//        String jsonFileName = "physical.fattree.json";
//
////		int fanout = 2;
//        int numPods = 8;	// Total hosts = (numPods^3)/4
//        double latency = 0.1;
//
//        long iops = 1000000000L;
//
//        int pe = 4;
//        long mips = 400;//8000;
//        int ram = 10240;
//        long storage = 10000000;
//        long bw = 125000000; //125MB = 1Gb
//        //long bw = 1000000000;
//
//        PhysicalTopologyGenerator reqg = new PhysicalTopologyGenerator();
//        HostSpec hostSpec = reqg.createHostSpec(pe, mips, ram, storage, bw);
////		reqg.createTreeTopology(hostSpec, iops, bw, fanout, latency);
//        reqg.createTopologyFatTree(hostSpec, iops, bw, numPods, latency);
//        reqg.wrtieJSON(jsonFileName);
//    }
//
//    public static void startTree() {
//        String jsonFileName = "wiki.physical.tree.json";
//
//        int fanout = 4;
//        int numPods = 8;	// Total hosts = (fanout^2) * numPods
//        int redundancy = 2;	// For aggr and core tier, how many switches are connected.
//        double latency = 0.1;
//
//        long iops = 1000000000L;
//
//        int pe = 8;
//        long mips = 2000;//8000;
//        int ram = 10240;
//        long storage = 10000000;
//        //long bw = 125000000;
//        long bw = 1000000000;
//
//        PhysicalTopologyGenerator reqg = new PhysicalTopologyGenerator();
//        HostSpec hostSpec = reqg.createHostSpec(pe, mips, ram, storage, bw);
//        reqg.createMultiLinkTreeTopology(hostSpec, iops,
//                bw, bw, bw,
//                latency, fanout, numPods, redundancy);
//        //reqg.createTopologyFatTree(hostSpec, iops, bw, numPods, latency);
//        reqg.wrtieJSON(jsonFileName);
//    }
//
//    protected void createTreeTopology(HostSpec hostSpec, long swIops, long swBw, int fanout, double latency) {
//        // core, aggregation, edge
//        // Core switch
//        SwitchSpec c = addSwitch("c", "core", swBw, swIops);
//
//        for (int i = 0; i < fanout; i++) {
//            SwitchSpec e = addSwitch("e" + i, "edge", swBw, swIops);
//            addLink(c, e, latency);
//
//            for (int j = 0; j < fanout; j++) {
//                String hostname = "h_" + i + "_" + j;
//                HostSpec h = addHost(hostname, hostSpec);
//                addLink(e, h, latency);
//            }
//        }
//    }
//
//    // This creates a 3 layer cannonical tree topology with redundant links on aggr and core layers
//    // https://www.grotto-networking.com/figures/BBNetVirtualizationDataCenter/DCNetworkConventional.png
//    protected void createMultiLinkTreeTopology(HostSpec hostSpec, long swIops,
//            long coreBw, long aggrBw, long edgeBw,
//            double latency, int fanout, int numPods, int redundancy) {
//        // core, aggregation, edge
//        // Core switch
//        SwitchSpec[] c = new SwitchSpec[redundancy];
//        for (int i = 0; i < redundancy; i++) {
//            c[i] = addSwitch("c_" + i, "core", coreBw, swIops);
//        }
//
//        for (int pod = 0; pod < numPods; pod++) {
//            SwitchSpec[] a = new SwitchSpec[redundancy];
//
//            for (int i = 0; i < redundancy; i++) {
//                a[i] = addSwitch("a" + pod + "_" + i, "aggregate", aggrBw, swIops);
//
//                // Add link between aggr - core
//                for (int j = 0; j < redundancy; j++) {
//                    addLink(a[i], c[j], latency);
//                }
//            }
//
//            for (int i = 0; i < fanout; i++) {
//                SwitchSpec e = addSwitch("e" + pod + "_" + i, "edge", edgeBw, swIops);
//                // Add link between aggr - edge
//                for (int j = 0; j < redundancy; j++) {
//                    addLink(a[j], e, latency);
//                }
//
//                for (int j = 0; j < fanout; j++) {
//                    String hostname = "h" + pod + "_" + i + "_" + j;
//                    HostSpec h = addHost(hostname, hostSpec);
//                    addLink(e, h, latency);
//                }
//            }
//        }
//    }
//
//    public static void CoapTerminate() {
//        for (int i = 0; i < Config.CoapServer_Number; i++) {
//            Config.CoapServers.get(i).HaltCoap();
//        }
//
//        for (int i = 0; i < Config.CoapClient_Number; i++) {
//            Config.CoapClients.get(i).HaltCoap();
//        }
//    }
//}
