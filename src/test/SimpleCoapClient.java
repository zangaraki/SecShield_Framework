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

import it.unipr.netsec.mjcoap.coap.client.CoapClient;
import it.unipr.netsec.mjcoap.coap.client.CoapResponseHandler;
import it.unipr.netsec.mjcoap.coap.message.CoapRequest;
import it.unipr.netsec.mjcoap.coap.message.CoapRequestMethod;
import it.unipr.netsec.mjcoap.coap.message.CoapResponse;
import it.unipr.netsec.mjcoap.coap.provider.CoapProvider;
import it.unipr.netsec.mjcoap.coap.provider.CoapURI;
import it.unipr.netsec.mjcoap.coap.server.CoapResource;

import java.net.SocketException;
import java.net.URISyntaxException;


/** Simple CoAP client.
 * It may send CoAP GET, PUT, and DELETE requests, or register for observing a remote resource.
 * <p>
 * It supports resource observation (RFC 7641) and blockwise transfer (RFC 7959). 
 */
public class SimpleCoapClient {
	
	/** Constructor is not available. */
	private SimpleCoapClient() {}


	/** The main method.
	 * @param args command-line arguments 
	 * @throws URISyntaxException 
	 * @throws SocketException */
	public static void main(String[] args) throws URISyntaxException, SocketException {
		Flags flags=new Flags(args);
		boolean help=flags.getBoolean("-h","prints this help");
		int local_port=flags.getInteger("-p","<port>",CoapProvider.DYNAMIC_PORT,"local UDP port (default port is "+CoapProvider.DEFAUL_PORT+")");
		int max_block_size=flags.getInteger("-m","<max-size>",0,"maximum block size");
		int verbose_level=flags.getInteger("-v","<level>",0,"verbose level");
		//boolean exit=flags.getBoolean("-x","stops observing when 'return' is pressed");
		String[] resource_tuple=flags.getStringTuple("-b",2,"<format> <value>",null,"resource value in PUT or POST requests; format can be: NULL|TEXT|XML|JSON; value can be ASCII or HEX (0x..)");
		int resource_format=resource_tuple!=null? CoapResource.getContentFormatIdentifier(resource_tuple[0]) : -1;
		byte[] resource_value=resource_tuple!=null? (resource_tuple[1].startsWith("0x")? ByteUtils.hexToBytes(resource_tuple[1]) : resource_tuple[1].getBytes()): null;
		String method_name=flags.getString(Flags.PARAM,"<method>",null,"method (e.g. GET, PUT, etc.)");
		String resource_uri=flags.getString(Flags.PARAM,"<uri>",null,"resource URI");
				
		if (help) {
			System.out.println(flags.toUsageString(SimpleCoapServer.class.getSimpleName()));
			System.exit(0);
		}
		
		if (verbose_level==1) SystemUtils.setDefaultLogger(new LoggerWriter(System.out,LoggerLevel.INFO));
		else
		if (verbose_level==2) SystemUtils.setDefaultLogger(new LoggerWriter(System.out,LoggerLevel.DEBUG));
		else
		if (verbose_level>=3) SystemUtils.setDefaultLogger(new LoggerWriter(System.out,LoggerLevel.TRACE));
		
		// client
		final CoapClient client=new CoapClient(local_port);
		if (max_block_size>0) client.setMaximumBlockSize(max_block_size);		
		
		// handler for receiving the response
		CoapResponseHandler resp_handler=new CoapResponseHandler() {
			@Override
			public void onResponse(CoapRequest req, CoapResponse resp) {
				byte[] value=resp.getPayload();
				String format=CoapResource.getContentFormat(resp.getContentFormat());
				System.out.println("Response: "+resp.getResponseCode()+": "+(format!=null? format+": " : "")+(value!=null? new String(value) : "void"));
				if (!req.hasObserveRegister()) {
					client.halt();
					System.exit(0);
				}
			}
			@Override
			public void onRequestFailure(CoapRequest req) {
				if (req.hasObserveRegister()) System.out.println("Observation finished");
				else System.out.println("Request failure");
				client.halt();
				System.exit(0);
			}
		};

		// request
		if (method_name.equalsIgnoreCase("OBSERVE")) {
			// resource observation
			CoapURI uri=new CoapURI(resource_uri);
			client.observe(uri,resp_handler);
			SystemUtils.readLine();
			client.observeCancel(uri);
		}
		else {
			// resource GET, PUT, POST, or DELETE
			client.request(CoapRequestMethod.getMethodByName(method_name),new CoapURI(resource_uri),resource_format,resource_value,resp_handler);
		}
	}

}
