/*
 * Title:        CloudSimSDN
 * Description:  SDN extension for CloudSim
 * Licence:      GPL - http://www.gnu.org/copyleft/gpl.html
 *
 * Copyright (c) 2015, The University of Melbourne, Australia
 */
package MyProject;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.cloudbus.cloudsim.Datacenter;
import org.cloudbus.cloudsim.Host;
import org.cloudbus.cloudsim.Log;
import org.cloudbus.cloudsim.Vm;
import org.cloudbus.cloudsim.VmAllocationPolicy;
import org.cloudbus.cloudsim.core.CloudSim;
import org.cloudbus.cloudsim.core.CloudSimTags;
import org.cloudbus.cloudsim.core.SimEntity;
import org.cloudbus.cloudsim.core.SimEvent;
import org.cloudbus.cloudsim.core.predicates.PredicateType;
import org.cloudbus.cloudsim.sdn.CloudSimEx;
import org.cloudbus.cloudsim.sdn.CloudSimTagsSDN;
import org.cloudbus.cloudsim.sdn.Configuration;
import org.cloudbus.cloudsim.sdn.LogWriter;
import org.cloudbus.cloudsim.sdn.physicalcomponents.Link;
import org.cloudbus.cloudsim.sdn.physicalcomponents.Node;
import org.cloudbus.cloudsim.sdn.physicalcomponents.PhysicalTopology;
import org.cloudbus.cloudsim.sdn.physicalcomponents.PhysicalTopologyInterCloud;
import org.cloudbus.cloudsim.sdn.physicalcomponents.SDNDatacenter;
import org.cloudbus.cloudsim.sdn.physicalcomponents.SDNHost;
import org.cloudbus.cloudsim.sdn.physicalcomponents.switches.Switch;
import org.cloudbus.cloudsim.sdn.policies.selectlink.LinkSelectionPolicy;
import org.cloudbus.cloudsim.sdn.policies.vmallocation.overbooking.OverbookingVmAllocationPolicy;
import org.cloudbus.cloudsim.sdn.sfc.ServiceFunction;
import org.cloudbus.cloudsim.sdn.sfc.ServiceFunctionAutoScaler;
import org.cloudbus.cloudsim.sdn.sfc.ServiceFunctionChainPolicy;
import org.cloudbus.cloudsim.sdn.sfc.ServiceFunctionForwarder;
import org.cloudbus.cloudsim.sdn.sfc.ServiceFunctionForwarderLatencyAware;
import org.cloudbus.cloudsim.sdn.virtualcomponents.FlowConfig;
import org.cloudbus.cloudsim.sdn.virtualcomponents.Channel;
import org.cloudbus.cloudsim.sdn.virtualcomponents.SDNVm;
import org.cloudbus.cloudsim.sdn.virtualcomponents.VirtualNetworkMapper;
import org.cloudbus.cloudsim.sdn.workload.Transmission;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;
import it.unipr.netsec.mjcoap.coap.message.CoapMessageType;
import java.io.IOException;
import java.util.AbstractList;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.cloudbus.cloudsim.sdn.nos.ChannelManager;

/**
 * NOS calculates and estimates network behaviour. It also mimics SDN Controller
 * functions. It manages channels between allSwitches, and assigns packages to
 * channels and control their completion Once the transmission is completed,
 * forward the packet to the destination.
 *
 * @author Jungmin Son
 * @author Rodrigo N. Calheiros
 * @since CloudSimSDN 1.0
 */
public abstract class NetworkOperatingSystem extends SimEntity {

    protected SDNDatacenter datacenter;

    // Physical topology
    protected PhysicalTopology topology;

    // Virtual topology
    protected VirtualNetworkMapper vnMapper = null;
    protected ChannelManager channelManager = null;
    protected boolean isApplicationDeployed = false;

    // Map: Vm ID -> VM
    protected HashMap<Integer, Vm> vmMapId2Vm = new HashMap<Integer, Vm>();

    // Global map (static): Vm ID -> VM
    protected static HashMap<Integer, Vm> gvmMapId2Vm = new HashMap<Integer, Vm>();

    // Vm ID (src or dst) -> all Flow from/to the VM
    protected Multimap<Integer, FlowConfig> flowMapVmId2Flow = HashMultimap.create();

    // Global map (static): Flow ID -> VM
    protected static Map<Integer, FlowConfig> gFlowMapFlowId2Flow = new HashMap<Integer, FlowConfig>();

    protected ServiceFunctionForwarder sfcForwarder;
    protected ServiceFunctionAutoScaler sfcScaler;

    // Resolution of the result.
    public static final long bandwidthWithinSameHost = 1500000000; // bandwidth between VMs within a same host: 12Gbps = 1.5GBytes/sec
    public static final double latencyWithinSameHost = 0.1; //0.1 msec latency 

    private double lastMigration = 0;
    private double lastAdjustAllChannelTime = -1;
    private double nextEventTime = -1;

    private int src, dst, flowId;
    private Packet pkt;
    HashMap<Integer, Integer> temp = new HashMap<Integer, Integer>();
    CoapMessage CM = new CoapMessage(CoapMessageType.NON, 2, 0);

    /**
     * 1. map VMs and middleboxes to hosts, add the new vm/mb to the
     * vmHostTable, advise host, advise dc 2. set channels and bws 3. set
     * routing tables to restrict hops to meet latency
     *
     * @param sfcPolicy
     */
    protected abstract boolean deployApplication(List<Vm> vms, Collection<FlowConfig> links, List<ServiceFunctionChainPolicy> sfcPolicy);

    public NetworkOperatingSystem(String name) {
        super(name);

        if (Configuration.SFC_LATENCY_AWARE_ENABLE) {
            this.sfcForwarder = new ServiceFunctionForwarderLatencyAware(this);
        } else {
            this.sfcForwarder = new ServiceFunctionForwarder(this);
        }

        this.vnMapper = new VirtualNetworkMapper(this);
        this.channelManager = new ChannelManager(this, vnMapper, sfcForwarder);

        this.sfcScaler = new ServiceFunctionAutoScaler(this, sfcForwarder);

        this.topology = new PhysicalTopologyInterCloud();
    }

    public void setLinkSelectionPolicy(LinkSelectionPolicy linkSelectionPolicy) {
        vnMapper.setLinkSelectionPolicy(linkSelectionPolicy);
    }

    public void configurePhysicalTopology(Collection<SDNHost> hosts, Collection<Switch> switches, Collection<Link> links) {
        for (SDNHost sdnHost : hosts) {
            topology.addNode(sdnHost);
        }

        for (Switch sw : switches) {
            topology.addNode(sw);
        }

        for (Link link : links) {
            topology.addLink(link);
        }

        topology.buildDefaultRouting();
    }

    @Override
    public void startEntity() {
        send(this.getId(), Configuration.monitoringTimeInterval, CloudSimTagsSDN.MONITOR_UPDATE_UTILIZATION);
    }

    @Override
    public void shutdownEntity() {

    }

    @Override
    public void processEvent(SimEvent ev) {
        int tag = ev.getTag();

        switch (tag) {
            case CloudSimTagsSDN.SDN_INTERNAL_CHANNEL_PROCESS:
                processInternalAdjustChannels();
                break;
            case CloudSimTagsSDN.SDN_INTERNAL_PACKET_PROCESS:
                processInternalPacketProcessing();
                break;
            case CloudSimTags.VM_CREATE_ACK:
                processVmCreateAck(ev);
                break;
            case CloudSimTags.VM_DESTROY:
                processVmDestroyAck(ev);
                break;
            case CloudSimTagsSDN.SDN_VM_CREATE_DYNAMIC_ACK:
                processVmCreateDynamicAck(ev);
                break;
            case CloudSimTagsSDN.MONITOR_UPDATE_UTILIZATION:
                if (this.datacenter != null) {
                    this.datacenter.processUpdateProcessing();
                }
                channelManager.updatePacketProcessing();

                this.updateBWMonitor(Configuration.monitoringTimeInterval);
                this.updateHostMonitor(Configuration.monitoringTimeInterval);
                this.updateSwitchMonitor(Configuration.monitoringTimeInterval);

                if (CloudSim.clock() >= lastMigration + Configuration.migrationTimeInterval && this.datacenter != null) {
                    sfcScaler.scaleSFC();	// Start SFC Auto Scaling

                    this.datacenter.startMigrate(); // Start Migration

                    lastMigration = CloudSim.clock();
                }
                this.updateVmMonitor(CloudSim.clock());

                if (CloudSimEx.hasMoreEvent(CloudSimTagsSDN.MONITOR_UPDATE_UTILIZATION)) {
                    double nextMonitorDelay = Configuration.monitoringTimeInterval;
                    double nextEventDelay = CloudSimEx.getNextEventTime() - CloudSim.clock();

                    // If there's no event between now and the next monitoring time, skip monitoring until the next event time. 
                    if (nextEventDelay > nextMonitorDelay) {
                        nextMonitorDelay = nextEventDelay;
                    }

                    long numPackets = channelManager.getTotalNumPackets();

                    System.err.println(CloudSim.clock() + ": Elasped time=" + CloudSimEx.getElapsedTimeString() + ", "
                            + CloudSimEx.getNumFutureEvents() + " more events," + " # packets=" + numPackets + ", next monitoring in " + nextMonitorDelay);
                    send(this.getId(), nextMonitorDelay, CloudSimTagsSDN.MONITOR_UPDATE_UTILIZATION);
                }
                break;
            default:
                System.out.println("Unknown event received by " + super.getName() + ". Tag:" + ev.getTag());
        }
    }

    protected void processVmCreateAck(SimEvent ev) {
//		SDNVm vm = (SDNVm) ev.getData();
//		Host host = findHost(vm.getId());
//		vm.setSDNHost(host);
    }

    protected void processVmCreateDynamicAck(SimEvent ev) {

        Object[] data = (Object[]) ev.getData();
        SDNVm newVm = (SDNVm) data[0];
        boolean result = (boolean) data[1];

        if (result) {
            Log.printLine(CloudSim.clock() + ": " + getName() + ".processVmCreateDynamic: Dynamic VM(" + newVm + ") creation succesful!");
            if (newVm instanceof ServiceFunction) {
                sfcForwarder.processVmCreateDyanmicAck((ServiceFunction) newVm);
            }
        } else {
            // VM cannot be created here..
            Log.printLine(CloudSim.clock() + ": " + getName() + ".processVmCreateDynamic: Dynamic VM cannot be created!! :" + newVm);
            System.err.println(CloudSim.clock() + ": " + getName() + ".processVmCreateDynamic: Dynamic VM cannot be created!! :" + newVm);
            sfcForwarder.processVmCreateDyanmicFailed((ServiceFunction) newVm);
        }
    }

    // Migrate network flow from previous routing
    public void processVmMigrate(Vm vm, SDNHost oldHost, SDNHost newHost) {
        // Find the virtual route associated with the migrated VM
        // VM is already migrated to the new host
        for (FlowConfig flow : this.flowMapVmId2Flow.get(vm.getId())) {
            SDNHost sender = findHost(flow.getSrcId());	// Sender will be the new host after migrated
            if (flow.getSrcId() == vm.getId()) {
                sender = oldHost;	// In such case, sender should be changed to the old host
            }
            vnMapper.rebuildForwardingTable(flow.getSrcId(), flow.getDstId(), flow.getFlowId(), sender);
        }

        // Move the transferring data packets in the old channel to the new one.
        migrateChannel(vm, oldHost, newHost);

        // Print all routing tables.
//		for(Node node:this.topology.getAllNodes()) {
//			node.printVMRoute();
//		}
    }

    private void processInternalPacketProcessing() {
        if (channelManager.updatePacketProcessing()) {
            sendInternalEvent();
        }
    }

    protected void processVmDestroyAck(SimEvent ev) {
        Vm destroyedVm = (Vm) ev.getData();
        // remove all channels transferring data from or to this vm.
        for (Vm vm : this.vmMapId2Vm.values()) {
            channelManager.removeChannel(vm.getId(), destroyedVm.getId(), -1);
            channelManager.removeChannel(destroyedVm.getId(), vm.getId(), -1);
        }
        sendInternalEvent();
    }

    protected void processInternalAdjustChannels() {
        channelManager.adjustAllChannel();
    }

    public boolean startDeployApplicatoin() {
        List<Vm> vms = new ArrayList<Vm>(vmMapId2Vm.values());
        List<ServiceFunctionChainPolicy> sfcPolicies = new ArrayList<ServiceFunctionChainPolicy>(sfcForwarder.getAllPolicies());
        boolean result = deployApplication(vms, this.flowMapVmId2Flow.values(), sfcPolicies);

        isApplicationDeployed = result;
        return result;
    }

    public void processCompletePackets(List<Channel> channels) {
        for (Channel ch : channels) {
            for (Transmission tr : ch.getArrivedPackets()) {
                Packet pkt = tr.getPacket();
                int vmId = pkt.getDestination();
                Datacenter dc = SDNDatacenter.findDatacenterGlobal(vmId);

                //Log.printLine(CloudSim.clock() + ": " + getName() + ": Packet completed: "+pkt +". Send to destination:"+ch.getLastNode());
                sendPacketCompleteEvent(dc, pkt, ch.getTotalLatency());
            }

            for (Transmission tr : ch.getFailedPackets()) {
                Packet pkt = tr.getPacket();
                sendPacketFailedEvent(this.datacenter, pkt, ch.getTotalLatency());
            }
        }
    }

    private void sendPacketCompleteEvent(Datacenter dc, Packet pkt, double latency) {
        send(dc.getId(), latency, CloudSimTagsSDN.SDN_PACKET_COMPLETE, pkt);
    }

    private void sendPacketFailedEvent(Datacenter dc, Packet pkt, double latency) {
        send(dc.getId(), latency, CloudSimTagsSDN.SDN_PACKET_FAILED, pkt);
    }

    public void sendAdjustAllChannelEvent() {
        if (CloudSim.clock() != lastAdjustAllChannelTime) {
            send(getId(), 0, CloudSimTagsSDN.SDN_INTERNAL_CHANNEL_PROCESS);
            lastAdjustAllChannelTime = CloudSim.clock();
        }
    }

    private void sendInternalEvent() {
        if (channelManager.getTotalChannelNum() != 0) {
            if (nextEventTime == CloudSim.clock() + CloudSim.getMinTimeBetweenEvents()) {
                return;
            }

            // More to process. Send event again
            double delay = channelManager.nextFinishTime();

            if (delay < CloudSim.getMinTimeBetweenEvents()) {
                //Log.printLine(CloudSim.clock() + ":Channel: delay is too short: "+ delay);
                delay = CloudSim.getMinTimeBetweenEvents();
            }

            //Log.printLine(CloudSim.clock() + ": " + getName() + ".sendInternalEvent(): delay for next event="+ delay);
            if ((nextEventTime > CloudSim.clock() + delay) || nextEventTime <= CloudSim.clock()) {
                //Log.printLine(CloudSim.clock() + ": " + getName() + ".sendInternalEvent(): next event time changed! old="+ nextEventTime+", new="+(CloudSim.clock()+delay));

                CloudSim.cancelAll(getId(), new PredicateType(CloudSimTagsSDN.SDN_INTERNAL_PACKET_PROCESS));
                send(this.getId(), delay, CloudSimTagsSDN.SDN_INTERNAL_PACKET_PROCESS);
                nextEventTime = CloudSim.clock() + delay;
            }
        }
    }

    public void updateChannelBandwidth(int src, int dst, int flowId, long newBandwidth) {
        if (channelManager.updateChannelBandwidth(src, dst, flowId, newBandwidth)) {
            // As the requested bandwidth updates, find alternative path if the current path cannot provide the new bandwidth.
            SDNHost sender = findHost(src);
            vnMapper.updateDynamicForwardingTableRec(sender, src, dst, flowId, false);

            sendAdjustAllChannelEvent();
        }
    }

    private void migrateChannel(Vm vm, SDNHost oldHost, SDNHost newHost) {
        for (Channel ch : channelManager.findAllChannels(vm.getId())) {
            List<Node> nodes = new ArrayList<Node>();
            List<Link> links = new ArrayList<Link>();

            SDNHost sender = findHost(ch.getSrcId());	// After migrated

            vnMapper.buildNodesLinks(ch.getSrcId(), ch.getDstId(),
                    ch.getChId(), sender, nodes, links);

            // update with the new nodes and links
            ch.updateRoute(nodes, links);
        }
    }

    public void addExtraVm(SDNVm vm, NetworkOperatingSystem callback) {
        vmMapId2Vm.put(vm.getId(), vm);
        gvmMapId2Vm.put(vm.getId(), vm);

        Log.printLine(CloudSim.clock() + ": " + getName() + ": Add extra VM #" + vm.getId()
                + " in " + datacenter.getName() + ", (" + vm.getStartTime() + "~" + vm.getFinishTime() + ")");

        Object[] data = new Object[2];
        data[0] = vm;
        data[1] = callback;

        send(datacenter.getId(), vm.getStartTime(), CloudSimTagsSDN.SDN_VM_CREATE_DYNAMIC, data);
    }

    public void removeExtraVm(SDNVm vm) {
        vmMapId2Vm.remove(vm.getId());
        gvmMapId2Vm.remove(vm.getId());

        Log.printLine(CloudSim.clock() + ": " + getName() + ": Remove extra VM #" + vm.getId()
                + " in " + datacenter.getName() + ", (" + vm.getStartTime() + "~" + vm.getFinishTime() + ")");

        send(datacenter.getId(), vm.getStartTime(), CloudSimTags.VM_DESTROY, vm);
    }

    public void addExtraPath(int orgVmId, int newVmId) {
        List<FlowConfig> newFlowList = new ArrayList<FlowConfig>();
        // This function finds all Flows involving orgVmId and add another virtual path for newVmId. 
        for (FlowConfig flow : this.flowMapVmId2Flow.get(orgVmId)) {
            int srcId = flow.getSrcId();
            int dstId = flow.getDstId();
            int flowId = flow.getFlowId();

            // Replace the source or destination with the new VM
            if (srcId == orgVmId) {
                srcId = newVmId;
            }
            if (dstId == orgVmId) {
                dstId = newVmId;
            }
            if (findVmGlobal(srcId) == null || findVmGlobal(dstId) == null) {
                continue;
            }

            FlowConfig extraFlow = new FlowConfig(srcId, dstId, flowId, flow.getBw(), flow.getLatency());
            newFlowList.add(extraFlow);

            if (vnMapper.buildForwardingTable(srcId, dstId, flowId) == false) {
                throw new RuntimeException("Cannot build a forwarding table!");
            }
        }

        for (FlowConfig flow : newFlowList) {
            insertFlowToMap(flow);
        }
    }

    public void updateVmMips(SDNVm orgVm, int newPe, double newMips) {
        Host host = orgVm.getHost();
        this.datacenter.getVmAllocationPolicy().deallocateHostForVm(orgVm);

        orgVm.updatePeMips(newPe, newMips);
        if (!this.datacenter.getVmAllocationPolicy().allocateHostForVm(orgVm, host)) {
            System.err.println("ERROR!! VM cannot be resized! " + orgVm + " (new Pe " + newPe + ", Mips " + newMips + ") in host: " + host);
            System.exit(-1);
        }
    }

    public long getRequestedBandwidth(int flowId) {
        FlowConfig flow = gFlowMapFlowId2Flow.get(flowId);
        if (flow != null) {
            return flow.getBw();
        }

        return 0L;
    }

    public double getRequestedBandwidth(Packet pkt) {
        int src = pkt.getOrigin();
        int dst = pkt.getDestination();
        int flowId = pkt.getFlowId();
        Channel channel = channelManager.findChannel(src, dst, flowId);
        double bw;
        if (channel == null) {
            bw = 0;
        } else {
            bw = channel.getRequestedBandwidth();
        }
        return bw;
    }

    public void updateBandwidthFlow(int srcVm, int dstVm, int flowId, long newBw) {
        if (flowId == -1) {
            return;
        }

        FlowConfig flow = gFlowMapFlowId2Flow.get(flowId);
        flow.updateReqiredBandwidth(newBw);
    }

    public void setDatacenter(SDNDatacenter dc) {
        this.datacenter = dc;
    }

    @Override
    public String toString() {
        return "NOS:" + getName();
    }

    public static Map<String, Integer> getVmNameToIdMap() {
        Map<String, Integer> map = new HashMap<>();
        for (Vm vm : gvmMapId2Vm.values()) {
            SDNVm svm = (SDNVm) vm;
            map.put(svm.getName(), svm.getId());
        }

        return map;
    }

    public static Map<String, Integer> getFlowNameToIdMap() {
        Map<String, Integer> map = new HashMap<String, Integer>();
        for (FlowConfig flow : gFlowMapFlowId2Flow.values()) {
            map.put(flow.getName(), flow.getFlowId());
        }

        map.put("default", -1);

        return map;
    }

    public PhysicalTopology getPhysicalTopology() {
        return this.topology;
    }

    @SuppressWarnings("unchecked")
    public <T extends Host> List<T> getHostList() {
        return (List<T>) topology.getAllHosts();
    }

    public List<Switch> getSwitchList() {
        return (List<Switch>) topology.getAllSwitches();
    }

    public boolean isApplicationDeployed() {
        return isApplicationDeployed;
    }

    public Vm findVmLocal(int vmId) {
        return vmMapId2Vm.get(vmId);
    }

    public static String getVmName(int vmId) {
        SDNVm vm = (SDNVm) gvmMapId2Vm.get(vmId);
        return vm.getName();
    }

    public static Vm findVmGlobal(int vmId) {
        return gvmMapId2Vm.get(vmId);
    }

    public SDNHost findHost(int vmId) {
        Vm vm = findVmLocal(vmId);
        if (vm != null) {
            // VM is in this NOS (datacenter)
            return (SDNHost) this.datacenter.getVmAllocationPolicy().getHost(vm);
        }

        // VM is in another data center. Find the host!
        vm = findVmGlobal(vmId);
        if (vm != null) {
            Datacenter dc = SDNDatacenter.findDatacenterGlobal(vmId);
            if (dc != null) {
                return (SDNHost) dc.getVmAllocationPolicy().getHost(vm);
            }
        }

        return null;
    }

    public void addVm(SDNVm vm) {
        vmMapId2Vm.put(vm.getId(), vm);
        gvmMapId2Vm.put(vm.getId(), vm);
    }

    private void insertFlowToMap(FlowConfig flow) {
        flowMapVmId2Flow.put(flow.getSrcId(), flow);
        flowMapVmId2Flow.put(flow.getDstId(), flow);
    }

    public void addFlow(FlowConfig flow) {
        insertFlowToMap(flow);

        if (flow.getFlowId() != -1) {
            gFlowMapFlowId2Flow.put(flow.getFlowId(), flow);
        }
    }

    public void addSFCPolicy(ServiceFunctionChainPolicy policy) {
        sfcForwarder.addPolicy(policy);
        List<FlowConfig> extraFlows = createExtraFlowSFCPolicy(policy);
        for (FlowConfig flow : extraFlows) {
            insertFlowToMap(flow);
        }
    }

    private List<FlowConfig> createExtraFlowSFCPolicy(ServiceFunctionChainPolicy policy) {
        // Add extra Flow for ServiceFunctionChain

        List<FlowConfig> flowList = new LinkedList<FlowConfig>();
        int flowId = policy.getFlowId();

        long bw = 0;
        double latency = 0.0;

        if (flowId != -1) {
            FlowConfig orgFlow = gFlowMapFlowId2Flow.get(flowId);
            bw = orgFlow.getBw();
            latency = orgFlow.getLatency();
        }

        List<Integer> vmIds = policy.getServiceFunctionChainIncludeVM();
        for (int i = 0; i < vmIds.size() - 1; i++) {
            // Build channel chain: SrcVM ---> SF1 ---> SF2 ---> DstVM
            int fromId = vmIds.get(i);
            int toId = vmIds.get(i + 1);

            FlowConfig sfcFlow = new FlowConfig(fromId, toId, flowId, bw, latency);
            flowList.add(sfcFlow);
        }

        policy.setInitialBandwidth(bw);
        return flowList;
    }

    // for monitoring
    private void updateBWMonitor(double monitoringTimeUnit) {
        double highest = 0;
        // Update utilization of all links
        Set<Link> links = new HashSet<Link>(this.topology.getAllLinks());
        for (Link l : links) {
            double util = l.updateMonitor(CloudSim.clock(), monitoringTimeUnit);
            if (util > highest) {
                highest = util;
            }
        }
        //System.err.println(CloudSim.clock()+": Highest utilization of Links = "+highest);

        channelManager.updateMonitor(monitoringTimeUnit);
    }

    private void updateHostMonitor(double monitoringTimeUnit) {
        if (datacenter != null) {
            for (SDNHost h : datacenter.<SDNHost>getHostList()) {
                h.updateMonitor(CloudSim.clock(), monitoringTimeUnit);
            }
        }
    }

    private void updateSwitchMonitor(double monitoringTimeUnit) {
        for (Switch s : getSwitchList()) {
            s.updateMonitor(CloudSim.clock(), monitoringTimeUnit);
        }
    }

    private void updateVmMonitor(double logTime) {
        if (datacenter == null) {
            return;
        }

        VmAllocationPolicy vmAlloc = datacenter.getVmAllocationPolicy();
        if (vmAlloc instanceof OverbookingVmAllocationPolicy) {
            for (Vm v : this.vmMapId2Vm.values()) {
                SDNVm vm = (SDNVm) v;
                double mipsOBR = ((OverbookingVmAllocationPolicy) vmAlloc).getCurrentOverbookingRatioMips((SDNVm) vm);
                LogWriter log = LogWriter.getLogger("vm_OBR_mips.csv");
                log.printLine(vm.getName() + "," + logTime + "," + mipsOBR);

                double bwOBR = ((OverbookingVmAllocationPolicy) vmAlloc).getCurrentOverbookingRatioBw((SDNVm) vm);
                log = LogWriter.getLogger("vm_OBR_bw.csv");
                log.printLine(vm.getName() + "," + logTime + "," + bwOBR);
            }
        }
    }

    public Vm getSFForwarderOriginalVm(int vmId) {
        return this.sfcForwarder.getOriginalSF(vmId);
    }

    public double calculateLatency(int srcVmId, int dstVmId, int flowId) {
        List<Node> nodes = new ArrayList<Node>();
        List<Link> links = new ArrayList<Link>();
        Node srcHost = findHost(srcVmId);
        vnMapper.buildNodesLinks(srcVmId, dstVmId, flowId, srcHost, nodes, links);

        double latency = 0;
        // Calculate the latency of the links.
        for (Link l : links) {
            latency += l.getLatencyInSeconds();
        }

        return latency;
    }

    /*
	protected void debugPrintMonitoredValues() {
		//////////////////////////////////////////////////////////////		
		//////////////////////////////////////////////////////////////
		// For debug only
		
		Collection<Link> links = this.topology.getAllLinks();
		for(Link l:links) {
			System.err.println(l);
			MonitoringValues mv = l.getMonitoringValuesLinkUtilizationUp();
			System.err.print(mv);
			mv = l.getMonitoringValuesLinkUtilizationDown();
			System.err.print(mv);
		}
//		
//		for(Channel ch:this.allChannels) {
//			System.err.println(ch);
//			MonitoringValues mv = ch.getMonitoringValuesLinkUtilization();
//			System.err.print(mv);
//		}
		
		for(SDNHost h:datacenter.<SDNHost>getHostList()) {
			System.err.println(h);
			MonitoringValues mv = h.getMonitoringValuesHostCPUUtilization();
			System.err.print(mv);			
		}

		for(Vm vm:vmMapId2Vm.values()) {
			SDNVm tvm = (SDNVm)vm;
			System.err.println(tvm);
			MonitoringValues mv = tvm.getMonitoringValuesVmCPUUtilization();
			System.err.print(mv);			
		}
	}
     */
    //-------------------------------------------------------------
    public static double Client_Checking(int client) { // AC
        System.out.println("client: " + client);
        double Sensivity = Double.parseDouble(
                Config.Client_Table.get(client).get(3)
        );
        return Sensivity;
    }

    public static void Function_Owner(int server) {
        if (server % Config.Server_Table.size() == 0) { // Directly
            Config.Server_Table.get(server % Config.Server_Table.size()).add("0");
        } else { // From domain
            Config.Server_Table.get(server % Config.Server_Table.size()).add("Domain number");
        }
    }

    public static void Function_ServiceDiscovery(int server) {
        Config.Server_Table.get(server % Config.Server_Table.size()).add(1, "server URI");
    }

    public static void Function_MDNS(int server) {
        Config.Server_Table.get(server % Config.Server_Table.size()).add(2, "server IP");
    }

    public Boolean Check_Security() {//Chech access control in TEMP
        boolean tag = false;

        System.out.println("Checking time flag....");//check in TEMP 
        if (!Objects.isNull(src) && !Objects.isNull(dst) && !Objects.isNull(temp)) {
            temp.put(src, dst);
            System.out.println("Checking time flag....1");//check Time expiration in TEMP
            System.out.println("(src , dst) = (" + src + " , " + dst + ")");
            //System.out.println("Config.Last_Request_Time.Size" + Config.Last_Request_Time.size());
            //double x = CloudSim.clock() - Config.Last_Request_Time.get(temp);
            if ((!Objects.isNull(Config.TEMP))
                    && (!Objects.isNull(Config.TEMP.get(temp)))// src, dsc
                    && (CloudSim.clock() - Config.TEMP.get(temp) + 10 > Config.Time_Flag)) {
                //   x = CloudSim.clock() - Config.Last_Request_Time.get(temp);
                System.out.println("Checking time flag....2");
                String vmName = ((SDNVm) findVmGlobal(src)).getName();

                try {
                    System.out.println("Checking Network access file....");
                    //------ Check Client attribute from Excel
                    ReadWriteExcelFile.FindInExcel("Network_access.xls", 0, src);
                    //------ Check Server attribute from Excel
                    ReadWriteExcelFile.FindInExcel("Network_access.xls", 1, dst);
                } catch (IOException ex) {
                    Logger.getLogger(NetworkOperatingSystem.class.getName()).log(Level.SEVERE, null, ex);
                }
                //------ ABAC
                
                List<ABAC_Policy> policies = ABAC_Policy.readPoliciesFromCSV("ABAC_Policy_Set.csv");
                boolean accessGranted = ABAC_Policy.evaluateAccess(Config.sub_att,Config.Action,Config.obj_att,Config.IP, policies);
                System.out.println("Access granted: " + accessGranted);

                tag=accessGranted;
            Config.AC++;
            } else {
                Config.No_AC++;
            }
        } else {
            tag = true;

        }
        return tag;
    }


    public Packet addPacketToChannel(Packet orgPkt) throws IOException {
        CoapMessage m = new CoapMessage();
        Config.Packet_Counter++;
        if (Config.Method.startsWith("Proposed")) {
            pkt = orgPkt;
            /*
		if(sender.equals(sender.getVMRoute(src, dst, flowId))) {
			// For loopback packet (when src and dst is on the same host)
			//Log.printLine(CloudSim.clock() + ": " + getName() + ".addPacketToChannel: Loopback package: "+pkt +". Send to destination:"+dst);
			sendNow(sender.getAddress(),Constants.SDN_PACKAGE,pkt);
			return;
		}
             */
            if (Configuration.ENABLE_SFC) {
                pkt = sfcForwarder.enforceSFC(pkt);
            }

            channelManager.updatePacketProcessing();

            flowId = pkt.getFlowId();
            src = pkt.getOrigin();
           
            dst = pkt.getDestination();

            //---------------------------------------
            Function_Owner(src);
            Function_ServiceDiscovery(src);
            Function_MDNS(src);

            //----------------------------------------------------------
            // Check timeline: If request < timeline then do not check
//        if (findVmGlobal(src) == null && Client_Checking(dst) > 0) {
//            src = getSFForwarderOriginalVm(dst).getId();
//            pkt.changeOrigin(dst);
//        }
            //---------------------------------------
            // Check if VM is removed by auto-scaling
            if (findVmGlobal(src) == null) {
                src = getSFForwarderOriginalVm(src).getId();
                pkt.changeOrigin(src);
            }
          
            if (findVmGlobal(dst) == null) {
                dst = getSFForwarderOriginalVm(dst).getId();
                pkt.changeDestination(dst);
            }
           

            //findHost(findVmGlobal(src).getId()).get
            //---------------------------------------------------------
            if (Check_Security()) {
                System.out.println("Security checked!");
                
                Channel channel = channelManager.findChannel(src, dst, flowId);
                       if (channel == null) {
                        //No channel established. Create a new channel.
                        SDNHost sender = findHost(src);
                        try {
                            channel = channelManager.createChannel(src, dst, flowId, sender);
                        } catch (Exception er) {
                            System.out.println(er.toString());
                        }
                        if (channel == null) {
                            // failed to create channel
                            System.err.println("ERROR!! Cannot create channel!" + pkt);
                            return pkt;
                        }
                        channelManager.addChannel(src, dst, flowId, channel);
                    }

                    channel.addTransmission(new Transmission(pkt));
//		Log.printLine(CloudSim.clock() + ": " + getName() + ".addPacketToChannel ("+channel
//				+"): Transmission added:" + 
//				NetworkOperatingSystem.getVmName(src) + "->"+
//				NetworkOperatingSystem.getVmName(dst) + ", flow ="+flowId + " / eft="+eft);

                    sendInternalEvent();

                    //-------------------------------------                
                
                Config.Allowed_Packets++;
            }
            //temp = null;
            temp.put(src, dst);
            Config.TEMP.put(temp, CloudSim.clock());
            //-------------------------------------
        } else if (Config.Method.startsWith("Base")) {
            pkt = orgPkt;
           
            if (Configuration.ENABLE_SFC) {
                pkt = sfcForwarder.enforceSFC(pkt);
            }

            channelManager.updatePacketProcessing();

            int src = pkt.getOrigin();
            int dst = pkt.getDestination();
            int flowId = pkt.getFlowId();

            Function_Owner(src);
            Function_ServiceDiscovery(src);
            Function_MDNS(src);

            // Check if VM is removed by auto-scaling
            if (findVmGlobal(src) == null) {
                src = getSFForwarderOriginalVm(src).getId();
                pkt.changeOrigin(src);
            }
            if (findVmGlobal(dst) == null) {
                dst = getSFForwarderOriginalVm(dst).getId();
                pkt.changeDestination(dst);
            }

            //---------------------------------------------------------
            boolean tag = false;
            temp.put(src, dst);
            if ((!Objects.isNull(Config.Last_Request_Time))
                    && (!Objects.isNull(Config.Last_Request_Time.get(temp)))// src, dsc
                    && (CloudSim.clock() - Config.Last_Request_Time.get(temp) + 10 > Config.Time_Flag)) {
                try {
                    ReadWriteExcelFile.FindInExcel("Network_access.xls", 0, src);
                    //------ Check Server from Excel
                    ReadWriteExcelFile.FindInExcel("Network_access.xls", 1, dst);
                } catch (IOException ex) {
                    Logger.getLogger(NetworkOperatingSystem.class.getName()).log(Level.SEVERE, null, ex);
                }
                System.out.println("Checking AC ....");
            /**************************************************************/
                Map<String, String> XML_Cheak = new HashMap<>();
                XML_Cheak.put("Location", String.valueOf(Config.Source));
                XML_Cheak.put("IP",Config.IP);
                XML_Cheak.put("URI",Config.URI);
                tag = MyXXACML.check(XML_Cheak);
                            
             /***********************************************************/   
                Config.AC++;
            } else {
                Config.No_AC++;//exppiration time not expired
                tag= true;
            }
    
            if (tag) {//CheckSecurity_Base()) {
                System.out.println("Security checked!");
                Channel channel = channelManager.findChannel(src, dst, flowId);
                if (channel == null) {
                    //No channel established. Create a new channel.
                    SDNHost sender = findHost(src);
                    try {
                        channel = channelManager.createChannel(src, dst, flowId, sender);
                    } catch (Exception er) {
                        System.out.println(er.toString());
                    }
                    if (channel == null) {
                        // failed to create channel
                        System.err.println("ERROR!! Cannot create channel!" + pkt);
                        return pkt;
                    }
                    channelManager.addChannel(src, dst, flowId, channel);
                }

                channel.addTransmission(new Transmission(pkt));

                sendInternalEvent();
                Config.Allowed_Packets++;
            }
            temp.put(src, dst);
            Config.Last_Request_Time.put(temp, CloudSim.clock());
        }
        return pkt;

    }

}
