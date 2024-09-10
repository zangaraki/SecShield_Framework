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

package it.unipr.netsec.mjcoap.coap.blockwise;


import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.mjcoap.coap.message.*;
import it.unipr.netsec.mjcoap.coap.provider.*;


/** Server-side support for blockwise transfers (RFC 7959).
 * <p>
 * It handles the request/response exchange in accord to the CoAP blockwise transfer extension.
 */
public class BlockwiseTransactionServer {
	
	/** Debug mode */
	static boolean DEBUG=true;
	//public static boolean DEBUG=false;

	/** Logs a debug message. */
	private void debug(String str) {
		if (DEBUG) SystemUtils.log(LoggerLevel.DEBUG,getClass(),str);
	}

	/** Logs a warning message.
	  * @param str the message to be logged */
	private void warning(String str) {
		SystemUtils.log(LoggerLevel.WARNING,getClass(),str);
	}

	
	/** Max server-side block size */
	int server_max_size=0;

	/** CoAP provider */
	CoapProvider coap_provider;
	
	/** Composed request */
	CoapRequest req;
	
	/** Composed response */
	//CoapResponse resp=null;

	/** Listener */
	BlockwiseTransactionServerListener listener;
	
	/** Whether the response has been sent */
	boolean response_sent=false;


	
	/**Creates a new BlockwiseTransactionServer.
	 * @param coap_provider the CoAP provider
	 * @param req the request message
	 * @param server_max_size the maximum size
	 * @param listener blockwise transaction server listener */
	public BlockwiseTransactionServer(CoapProvider coap_provider, CoapRequest req, int server_max_size, BlockwiseTransactionServerListener listener) {
		debug("BlockwiseTransactionServer()");
		this.coap_provider=coap_provider;
		this.req=req;
		this.server_max_size=server_max_size;
		this.listener=listener;
		Block1ServerListener this_b1s_listener=new Block1ServerListener() {
			public void onReceivedRequest(Block1Server block1_server, CoapRequest req) {
				processReceivedRequest(block1_server,req);
			}
		};
		new Block1Server(coap_provider,req,server_max_size,this_b1s_listener);
	}
	
	
	/** When a new CoAP request message is completely received (transferred).
	 * @param block1_server the blockwise transfer server
	 * @param req the received CoAP request */
	private synchronized void processReceivedRequest(Block1Server block1_server, CoapRequest req) {
		this.req=req;
		debug("processReceivedRequest(): request passed to listener: "+listener);
		if (listener!=null) listener.onReceivedRequest(this,req);
	}
	

	/** Sends CoAP response.
	 * @param resp the response message */
	public synchronized void respond(CoapResponse resp) {
		if (response_sent) {
			warning("respond(): response message already sent");
			return;
		}
		// else
		response_sent=true;
		//this.resp=resp;
		new Block2Server(coap_provider,req,server_max_size).respond(resp);
	}
	
}
