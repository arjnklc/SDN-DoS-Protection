
package arj.app;


import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleEvent;
// import org.onosproject.net.flow.FlowRuleListener;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.EthCriterion;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.Optional;
import java.util.Timer;
import java.util.TimerTask;

import java.util.ArrayList;

import java.util.Collections;

import static org.onosproject.net.flow.FlowRuleEvent.Type.RULE_REMOVED;
import static org.onosproject.net.flow.criteria.Criterion.Type.ETH_SRC;



@Component(immediate = true)
public class AppComponent {

    private Logger log = LoggerFactory.getLogger(getClass());

    private static final String DOS_WARNING = "DOS Attack detected. Packet is dropped.";

    private static final String START_MESSAGE = "DOS Protection Activated.";
    private static final String STOP_MESSAGE = "DOS Protection Stopped";


    private static final int PRIORITY = 128;
    private static final int TIMEOUT = 1;   // 1 second


    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PacketService packetService;

    ApplicationId applicationId;
    private final PacketProcessor packetProcessor = new MyPacketProcessor();

    private final TrafficSelector ts = DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV4).build();


    // Records of all packets in last 1 second
    private ArrayList<PacketRecord> allPackets = new ArrayList();
    Timer timer = new Timer();


    @Activate
    public void activate() {
        applicationId = coreService.registerApplication("org.foo.app");
        packetService.addProcessor(packetProcessor, PRIORITY);
        packetService.requestPackets(ts, PacketPriority.CONTROL, applicationId, Optional.empty());
        log.info(START_MESSAGE);
    }

    @Deactivate
    public void deactivate() {
        packetService.removeProcessor(packetProcessor);
        flowRuleService.removeFlowRulesById(applicationId);
        log.info(STOP_MESSAGE);
    }


    private boolean isFlood(PacketRecord packet) {
        try {
            // if there is already 15 similar packets in the cache, it is flood.
            boolean is_a_lot_packet = Collections.frequency(allPackets, packet) > 15;

            return is_a_lot_packet;
        }
        catch (Exception e) {
            return true;
        }
    }

    // Processes the specified packet.
    private void processPacket(PacketContext context, Ethernet eth) {
        DeviceId deviceId = context.inPacket().receivedFrom().deviceId();

        MacAddress sourceMAC = eth.getSourceMAC();
        MacAddress destMac = eth.getDestinationMAC();

        PacketRecord packet = new PacketRecord(sourceMAC, destMac, context);
        // boolean sent_before = allPackets.get(deviceId).contains(packet);
        boolean flood = isFlood(packet);

        String c = context.inPacket().parsed().toString();

        short p = ( (IPv4) eth.getPayload() ).getTotalLength();

        // if it is a flood, ban similar packets for 1 second and drop the packet
        if (flood) {
            log.warn(DOS_WARNING);

            banPacket(deviceId, sourceMAC, destMac);
            context.block();
        }

        // else, save the packet to the allPackets list for 1 second.
        else {
            String s = "packet from {} to {} ";
            log.info(s, sourceMAC, destMac);
            allPackets.add(packet);
            //allPackets.put(deviceId, packet);
            PacketCleaner cleaner = new PacketCleaner(packet);
            timer.schedule(cleaner, TIMEOUT * 1000);
        }
    }

    // Add a temporary drop rule for the packets between two mac addresses
    private void banPacket(DeviceId deviceId, MacAddress sourceMac, MacAddress destMac) {
        TrafficSelector ts = DefaultTrafficSelector.builder().matchEthSrc(sourceMac).matchEthDst(destMac).build();
        TrafficTreatment tt = DefaultTrafficTreatment.builder().drop().build();

        try {
            flowObjectiveService.forward(deviceId, DefaultForwardingObjective.builder()
                    .fromApp(applicationId)
                    .withSelector(ts)
                    .withTreatment(tt)
                    .withFlag(ForwardingObjective.Flag.VERSATILE)
                    .withPriority(PRIORITY + 1)
                    .makeTemporary(TIMEOUT)
                    .add());
        }
        catch (Exception e) {

        }

    }


    private boolean is_IPv4_Packet(Ethernet eth) {
        return eth.getEtherType() == Ethernet.TYPE_IPV4;
    }

    // Intercepts packets
    private class MyPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            Ethernet eth = context.inPacket().parsed();

            // check if packet is IPv4, if so process
            if (is_IPv4_Packet(eth)) {
                processPacket(context, eth);
            }
        }
    }

    // Record of a network packet between two mac addresses
    private class PacketRecord {
        private final MacAddress sourceMac;
        private final MacAddress destMac;
        private final PacketContext context;

        PacketRecord(MacAddress sourceMac, MacAddress destMac, PacketContext context) {
            this.sourceMac = sourceMac;
            this.destMac = destMac;
            this.context = context;
        }

        @Override
        public int hashCode() {
            return Objects.hash(sourceMac, destMac);
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == null || getClass() != obj.getClass()) {
                return false;
            }

            PacketRecord other = (PacketRecord) obj;

            String c = this.context.inPacket().parsed().toString();
            String d = other.context.inPacket().parsed().toString();

            Ethernet eth1 = this.context.inPacket().parsed();
            Ethernet eth2 = other.context.inPacket().parsed();

            short len1 = ( (IPv4) eth1.getPayload() ).getTotalLength();
            short len2 = ( (IPv4) eth2.getPayload() ).getTotalLength();

            return Objects.equals(this.destMac, other.destMac) &&
                   len1 == len2;
        }

    }

    private class PacketCleaner extends TimerTask {
        PacketRecord packet;

        public PacketCleaner(PacketRecord packet) {
            this.packet = packet;
        }

        @Override
        public void run() {
            try {
                allPackets.remove(packet);
            }
            catch (Exception e) {

            }
        }
    }


}
