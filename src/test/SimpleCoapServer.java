/*
 * Copyright (c) 2018 NetSec Lab - University of Parma (Italy)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND. IN NO EVENT
 * SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Author(s):
 * Luca Veltri (luca.veltri@unipr.it)
 */

package test;


import org.zoolu.util.ByteUtils;
import org.zoolu.util.Flags;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.LoggerWriter;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.mjcoap.coap.provider.CoapProvider;
import it.unipr.netsec.mjcoap.coap.server.CoapResource;
import it.unipr.netsec.mjcoap.coap.server.CoapServer;

import java.net.SocketException;
import java.util.HashSet;
import java.util.Iterator;


/** Ready-to-use simple stateful CoAP server.
 * It handles CoAP GET, PUT, and DELETE requests statefully, automatically handling request and response retransmissions.
 * <p>
 * It supports resource observation (RFC 7641) and blockwise transfer (RFC 7959). 
 */
public class SimpleCoapServer {
		
	/** Constructor is not available. */
	private SimpleCoapServer() {}

	
	/** The main method. 
	 * @throws SocketException */
	public static void main(String[] args) throws SocketException {
		Flags flags=new Flags(args);
		boolean help=flags.getBoolean("-h","prints this help");
		int local_port=flags.getInteger("-p","<port>",CoapProvider.DEFAUL_PORT,"server UDP port (default port is "+CoapProvider.DEFAUL_PORT+")");
		int max_block_size=flags.getInteger("-m","<max-size>",0,"maximum block size");
		int verbose_level=flags.getInteger("-v","<level>",0,"verbose level");
		boolean write_mode=flags.getBoolean("-w","server in write-enabled mode");
		boolean exit=flags.getBoolean("-x","exits if 'return' is pressed");
		HashSet<CoapResource> resources=new HashSet<CoapResource>();
		String[] resource_tuple=flags.getStringTuple("-a",3,"<name> <format> <value>",null,"add a resource; format can be: NULL|TEXT|XML|JSON; value can be ASCII or HEX (0x..)");
		while (resource_tuple!=null) {
			String resource_name=resource_tuple[0];
			int resource_format=CoapResource.getContentFormatIdentifier(resource_tuple[1]);
			String str=resource_tuple[2];
			byte[] resource_value=str.startsWith("0x")? ByteUtils.hexToBytes(str) : str.getBytes();
			CoapResource res=new CoapResource(resource_name,resource_format,resource_value);
			resources.add(res);
			System.out.println("Adding server resource: "+res);
			resource_tuple=flags.getStringTuple("-a",3,null,null,null);
		}
		
		if (help) {
			System.out.println(flags.toUsageString(SimpleCoapServer.class.getSimpleName()));
			System.exit(0);
		}
		if (verbose_level==1) SystemUtils.setDefaultLogger(new LoggerWriter(System.out,LoggerLevel.INFO));
		else
		if (verbose_level==2) SystemUtils.setDefaultLogger(new LoggerWriter(System.out,LoggerLevel.DEBUG));
		else
		if (verbose_level>=3) SystemUtils.setDefaultLogger(new LoggerWriter(System.out,LoggerLevel.TRACE));

		CoapServer server=new CoapServer(local_port);
		if (write_mode) server.setWriteMode(true);
		if (max_block_size>0) server.setMaximumBlockSize(max_block_size);
		System.out.println("CoAP server running on port: "+local_port);
		System.out.println("Write mode: "+(write_mode? "enabled":"disabled"));
		if (max_block_size>0) System.out.println("Maximum block size: "+max_block_size);
		
		for (Iterator<CoapResource> i=resources.iterator(); i.hasNext(); ) {
			CoapResource res=i.next();
			server.setResource(res.getName(),res.getFormat(),res.getValue());
		}
		
		if (exit) {
			//System.out.println("Press 'Return' to exit..");
			SystemUtils.readLine();
			server.halt();
			System.exit(0);
		}
	}

}
