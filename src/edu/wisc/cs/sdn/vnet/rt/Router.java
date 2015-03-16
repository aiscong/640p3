package edu.wisc.cs.sdn.vnet.rt;

import java.nio.ByteBuffer;
import java.util.*;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.*;
/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */

class Pair {
	Ethernet e;
	Iface in;
	Pair(Ethernet ep, Iface inFace){
		e = ep;
		in = inFace;
	}
}

class PktInfo{
	Ethernet req;
	Iface out;
	int count;
	PktInfo(Ethernet r, Iface outface){
		req = r;
		out = outface;
		count = 0;
	}
}

public class Router extends Device {	
	private static final int TIMEEX = 0;
	private static final int UNREACHNET = 1;
	private static final int UNREACHHOST = 2;
	private static final int UNREACHPORT = 3;
	//private static final int ECHOREPLY = 4;
	/** Routing table for the router */
	private RouteTable routeTable;
	private Map<Integer, PktInfo> requests;
	/** ARP cache for the router */
	private ArpCache arpCache;
	private Timer t;
	private Map<Integer, Queue<Pair>> arpReqQueue;

	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile) {
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
		this.arpReqQueue = new HashMap<Integer, Queue<Pair>>();
		this.requests = new HashMap<Integer, PktInfo>();
		this.t = new Timer();
		t.scheduleAtFixedRate(new TimerTask(){
			@Override
			public void run(){
				for(Map.Entry<Integer, PktInfo> i : requests.entrySet()){
					if(i.getValue().count < 3){
						sendPacket(i.getValue().req, i.getValue().out);
						i.getValue().count++;
					}else if(i.getValue().count == 3){
						Queue<Pair> temp = arpReqQueue.get(i.getKey());
						while(!temp.isEmpty()){
							Pair pp = temp.poll();
							icmpPacket(pp.e, pp.in, UNREACHHOST);
						}
						arpReqQueue.remove(i.getKey());
						requests.remove(i.getKey());
					}
					else{
						System.out.println("Count is weird.....");
					}
				}
			}
		}, 0L, 1000L);
	}
	
	/**
	 * Start RIP if no static route table is provided
	 * Add every directly accessible entries to its route table
	 * send out RIP requests
	 */
	public void startRIP(){
		for (Iface iface : this.interfaces.values()) {
			this.routeTable.insert(iface.getIpAddress(), 0, iface.getSubnetMask(), iface);
		}
	}
	
	/**
	 * prototype of an RIP packet
	 * a snap shot of current route table
	 */
	public Ethernet genRIP(byte type){
		Ethernet eout = new Ethernet();
		IPv4 ip = new IPv4();
		UDP u = new UDP();
		RIPv2 r = new RIPv2();
		for(RouteEntry e : this.routeTable.getAll()){
			RIPv2Entry ripEnt = new RIPv2Entry()
		}
	}
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }

	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}

		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}

	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}

		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface){
		System.out.println("*** -> Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));

		/********************************************************************/
		/* TODO: Handle packets                                             */

		switch(etherPacket.getEtherType()){
		case Ethernet.TYPE_IPv4:
			this.handleIpPacket(etherPacket, inIface);
			break;
			// Ignore all other packet types, for now

		case Ethernet.TYPE_ARP:
			ARP ap = (ARP)etherPacket.getPayload();
			if(ap.getOpCode() == ARP.OP_REQUEST){
				System.out.println("receive a request");
				arpGenRep(etherPacket, inIface);
			}else if(ap.getOpCode() == ARP.OP_REPLY){
				arpRecRep(ap, inIface);
			}
			break;
		}
		/********************************************************************/
	}

	private Ethernet arpGenReq(Ethernet e, Iface out, int targetIP){
		System.out.println("Generating Arp Request");

		Ethernet eout = new Ethernet();
		eout.setEtherType(Ethernet.TYPE_ARP);
		eout.setSourceMACAddress(out.getMacAddress().toBytes());
		byte [] broadcast = new byte[MACAddress.MAC_ADDRESS_LENGTH];
		Arrays.fill(broadcast, (byte)0xff);
		eout.setDestinationMACAddress(broadcast);
		//construct arp header
		ARP aout = new ARP();
		aout.setHardwareType(ARP.HW_TYPE_ETHERNET);
		aout.setProtocolType(ARP.PROTO_TYPE_IP);
		aout.setHardwareAddressLength((byte)Ethernet.DATALAYER_ADDRESS_LENGTH);
		aout.setProtocolAddressLength((byte)4);
		aout.setOpCode(ARP.OP_REQUEST);
		aout.setSenderHardwareAddress(out.getMacAddress().toBytes());
		aout.setSenderProtocolAddress(out.getIpAddress());
		byte [] zeros = new byte[MACAddress.MAC_ADDRESS_LENGTH];
		aout.setTargetHardwareAddress(zeros);
		aout.setTargetProtocolAddress(targetIP);
		//wrap arp packet under etherpacket
		eout.setPayload(aout);
		System.out.println("Arp Req ready to send");
		return eout;
	}


	private void arpGenRep(Ethernet e, Iface in){
		ARP ap = (ARP)e.getPayload();
		int targetIp = ByteBuffer.wrap(ap.getTargetProtocolAddress()).getInt();
		//not targeted to incoming iface
		if(targetIp != in.getIpAddress()) return;
		System.out.println("[Success] it targets to incoming interface");
		//construct ether header
		Ethernet eout = new Ethernet();
		eout.setEtherType(Ethernet.TYPE_ARP);
		eout.setSourceMACAddress(in.getMacAddress().toBytes());
		eout.setDestinationMACAddress(e.getSourceMACAddress());
		//construct arp header
		ARP aout = new ARP();
		aout.setHardwareType(ARP.HW_TYPE_ETHERNET);
		aout.setProtocolType(ARP.PROTO_TYPE_IP);
		aout.setHardwareAddressLength((byte)Ethernet.DATALAYER_ADDRESS_LENGTH);
		aout.setProtocolAddressLength((byte)4);
		aout.setOpCode(ARP.OP_REPLY);
		aout.setSenderHardwareAddress(in.getMacAddress().toBytes());
		aout.setSenderProtocolAddress(in.getIpAddress());
		aout.setTargetHardwareAddress(ap.getSenderHardwareAddress());
		aout.setTargetProtocolAddress(ap.getSenderProtocolAddress());
		//wrap arp packet under etherpacket
		eout.setPayload(aout);
		System.out.println("ready to send reply");
		this.sendPacket(eout, in);
	}
	private void arpRecRep(ARP ap, Iface in){
		System.out.println("Arp rep Received!");
		int senderIp = IPv4.toIPv4Address(ap.getSenderProtocolAddress());
		if(arpCache.lookup(senderIp) != null) {
			System.out.println("has added this entry to arp cache before!");
			return;
		}
		int targetIp = ByteBuffer.wrap(ap.getTargetProtocolAddress()).getInt();
		System.out.println("targetIp: " + targetIp + " inIface: " + in.getIpAddress());
		if(targetIp != in.getIpAddress()) return;
		System.out.println("targetIp inIface match");
		MACAddress targethw = new MACAddress(ap.getTargetHardwareAddress());
		if(!targethw.equals(in.getMacAddress())) return;
		System.out.println("target HW address matched");
		if(!arpReqQueue.containsKey(senderIp)) return;
		System.out.println("[Success] find waiting queue");
		arpCache.insert(new MACAddress(ap.getSenderHardwareAddress()), senderIp);
		System.out.println("AFTER ADD IN ARP CACHE");
		System.out.println("----arp cache is after processing the reply----\n" + this.arpCache.toString());
		Queue<Pair> q = this.arpReqQueue.get(senderIp);
		while(!q.isEmpty()){
			System.out.println("--- dequeuing ---");
			Pair cur = q.poll();
			cur.e.setDestinationMACAddress(ap.getSenderHardwareAddress());
			this.sendPacket(cur.e, this.requests.get(senderIp).out);
		}
		this.requests.remove(senderIp);
		this.arpReqQueue.remove(senderIp);
		System.out.println("all done in receiving arp reply");
	}

	private void handleIpPacket(Ethernet etherPacket, Iface inIface){
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) return;
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		System.out.println("Handle IP packet");

		// Verify checksum
		short origCksum = ipPacket.getChecksum();
		ipPacket.resetChecksum();
		byte[] serialized = ipPacket.serialize();
		ipPacket.deserialize(serialized, 0, serialized.length);
		short calcCksum = ipPacket.getChecksum();
		if (origCksum != calcCksum)
		{ return; }

		// Check TTL
		ipPacket.setTtl((byte)(ipPacket.getTtl()-1));
		System.out.println("ttl is " + ipPacket.getTtl());
		//send time exceeded icmp
		if (0 == ipPacket.getTtl()){
			System.out.println("---------------TIME EX LIMIT --------------------");
			this.icmpPacket(etherPacket, inIface, TIMEEX);
			return;
		}
		// Reset checksum now that TTL is decremented
		ipPacket.resetChecksum();
		// Check if packet is destined for one of router's interfaces
		for (Iface iface : this.interfaces.values()) {
			if (ipPacket.getDestinationAddress() == iface.getIpAddress()){
				if(ipPacket.getProtocol() == IPv4.PROTOCOL_TCP || 
						ipPacket.getProtocol() == IPv4.PROTOCOL_UDP){ 	
					this.icmpPacket(etherPacket, inIface, UNREACHPORT);
				}
				else if (ipPacket.getProtocol() == IPv4.PROTOCOL_ICMP) {
					ICMP icmpPacket = (ICMP)ipPacket.getPayload();
					if(icmpPacket.getIcmpType() == ICMP.TYPE_ECHO_REQUEST){
						this.echoReply(etherPacket, inIface);
					}
				}
				return; 
			}
		}

		// Do route lookup and forward
		this.forwardIpPacket(etherPacket, inIface);
	}

	private void forwardIpPacket(Ethernet etherPacket, Iface inIface){
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) return;
		System.out.println("Forward IP packet");

		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		int dstAddr = ipPacket.getDestinationAddress();

		// Find matching route table entry 
		RouteEntry bestMatch = this.routeTable.lookup(dstAddr);
		// send unreachable net icmp If no entry matched in routeTable
		if (null == bestMatch){ 
			System.out.println("IP dst addrs " + IPv4.fromIPv4Address(ipPacket.getDestinationAddress()));
			this.icmpPacket(etherPacket, inIface, UNREACHNET);
			return; 
		}

		// Make sure we don't sent a packet back out the interface it came in
		Iface outIface = bestMatch.getInterface();
		if (outIface == inIface) return;

		// Set source MAC address in Ethernet header
		etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

		// If no gateway, then nextHop is IP destination
		int nextHop = bestMatch.getGatewayAddress();
		if (0 == nextHop){ 
			nextHop = dstAddr; 
		}

		// Set destination MAC address in Ethernet header
		ArpEntry arpEntry = this.arpCache.lookup(nextHop);
		if (null == arpEntry){
			//Generate ARP Request
			if(!this.arpReqQueue.containsKey(nextHop)){
				System.out.println("No queue found for this hop");
				if(!this.requests.containsKey(nextHop)){
					System.out.println("No request found for this hop");
					System.out.println("first time miss");
					Queue<Pair> newQueue = new LinkedList<Pair>();
					Pair pp = new Pair(etherPacket, inIface);
					newQueue.add(pp);
					arpReqQueue.put(nextHop, newQueue);
					System.out.println("Arp Queue initialized");	
					PktInfo pi = new PktInfo(arpGenReq(etherPacket, outIface, nextHop), outIface);
					this.requests.put(nextHop, pi);
					System.out.println("new request entry added");
				}else{
					System.out.println("Not consistent");
				}
			}else{
				System.out.println("already had a queue");
				if(!this.requests.containsKey(nextHop)){
					System.out.println("[inconsistent] but no request entry");
				}else{
					System.out.println("add new packet to a waiting queue");
					this.arpReqQueue.get(nextHop).add(new Pair(etherPacket, inIface));
				}
			}
		}else{
			System.out.println("====found a match in arp cache at the first place====");
			etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
			this.sendPacket(etherPacket, outIface);
		}
	}

	private void echoReply(Ethernet ep, Iface in){
		if (ep.getEtherType() != Ethernet.TYPE_IPv4) return;
		IPv4 p = (IPv4) ep.getPayload();
		System.out.println("Echo Reply");

		Ethernet ether = new Ethernet();
		IPv4 ip = new IPv4();
		ICMP icmp = new ICMP();
		//Data data = new Data();

		//populate ethernet headers
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(in.getMacAddress().toBytes());
		RouteEntry routeMatch = this.routeTable.lookup(p.getSourceAddress());
		if(routeMatch == null){	
			System.out.println("Send back routeEntry not found!");
			return;
		}
		int dst = routeMatch.getGatewayAddress();
		if(dst == 0)
			dst = p.getSourceAddress();
		ArpEntry arpMatch = this.arpCache.lookup(dst);
		if(arpMatch == null){
			System.out.println("Send back arp not found!");
			return;
		}
		ether.setDestinationMACAddress(arpMatch.getMac().toBytes());

		//populate ip header
		ip.setTtl((byte)64);
		ip.setProtocol(IPv4.PROTOCOL_ICMP);
		ip.setSourceAddress(p.getDestinationAddress());
		ip.setDestinationAddress(p.getSourceAddress());

		//populate ICMP header
		//ICMP tempIcmp = (ICMP)p.getPayload();
		byte[] icmpPayload = p.getPayload().serialize();
		icmp.deserialize(icmpPayload, 0, icmpPayload.length);
		icmp.setIcmpType((byte)0);
		icmp.setIcmpCode((byte)0);
		ether.setPayload(ip);
		ip.setPayload(icmp);
		//icmp.setPayload(data);	
		this.sendPacket(ether, in);
	}

	private void icmpPacket(Ethernet ep, Iface in, int opt){
		if (ep.getEtherType() != Ethernet.TYPE_IPv4) return;
		System.out.println("Generating ICMP packet " + opt);
		System.out.println("[Success]incoming is an ipv4");
		IPv4 p = (IPv4)(ep.getPayload());

		//Ethernet type -> IPv4
		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_IPv4);
		//set source MAC as incoming interface MAC
		ether.setSourceMACAddress(in.getMacAddress().toBytes());
		//look up routeTable based on source ip
		RouteEntry rent = null;
		rent = this.routeTable.lookup(p.getSourceAddress());
		if(rent == null) return;
		System.out.println("[Success]incoming has a match in route table");

		//set destination MAC as ARP cache lookup result
		ArpEntry arpent = null;
		arpent = rent.getGatewayAddress() == 0 ? this.arpCache.lookup(p.getSourceAddress()) : this.arpCache.lookup(rent.getGatewayAddress());
		if(arpent == null) return;
		System.out.println("[Success]incoming has a match in arp cache");
		ether.setDestinationMACAddress(arpent.getMac().toBytes());
		IPv4 ip = new IPv4();
		ip.setTtl((byte)64);
		ip.setProtocol(IPv4.PROTOCOL_ICMP);
		ip.setSourceAddress(in.getIpAddress());
		ip.setDestinationAddress(p.getSourceAddress());

		//set ICMP code and type value according to error type
		ICMP icmp = new ICMP();
		switch(opt){
		case TIMEEX:		
			System.out.println("TIMEEX");
			icmp.setIcmpType((byte)11);
			icmp.setIcmpCode((byte)0);
			break;

		case UNREACHNET:	
			System.out.println("UNREACHNET");
			icmp.setIcmpType((byte)3);
			icmp.setIcmpCode((byte)0);
			break;

		case UNREACHHOST:	
			System.out.println("UNREACHHOST");
			icmp.setIcmpType((byte)3);
			icmp.setIcmpCode((byte)1);
			break;

		case UNREACHPORT: 	
			System.out.println("UNREACHPORT");
			icmp.setIcmpType((byte)3);
			icmp.setIcmpCode((byte)3);
			break;

		default:		
			System.out.println("Wrong opt!");
			break;
		}

		Data data = new Data();
		byte[] icmpPayload = new byte[12+p.getHeaderLength()*4];
		ByteBuffer bb = ByteBuffer.wrap(icmpPayload);
		bb.position(4); //padding 4 bytes
		byte[] ip4packet = p.serialize();
		bb.put(ip4packet, 0, p.getHeaderLength()*4 + 8); //put ip header and 8 bytes after ip header

		data.setData(icmpPayload);
		System.out.println("construct payload of icmp " + (bb.position() == p.getHeaderLength()*4 + 12));

		ether.setPayload(ip);
		ip.setPayload(icmp);
		icmp.setPayload(data);

		//send it on the same interface on which the original packet arrived
		this.sendPacket(ether, in);
	}
}


