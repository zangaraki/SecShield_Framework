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


import java.net.InetSocketAddress;

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.mjcoap.coap.message.*;
import it.unipr.netsec.mjcoap.coap.option.Block2Option;
import it.unipr.netsec.mjcoap.coap.option.CoapOptionNumber;
import it.unipr.netsec.mjcoap.coap.provider.CoapProvider;


/** Client-side support for blockwise transfers (RFC 7959).
 * <p>
 * It handles the request/response exchange in accord to the CoAP blockwise transfer extension.
 */
public class BlockwiseTransactionClient {
	
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

	
	/** Max client-side block size */
	int client_max_size=0;

	/** CoAP provider */
	CoapProvider coap_provider;

	/** Remote socket address */
	InetSocketAddress remote_soaddr;

	/** Request message */
	CoapRequest req;
	
	/** Blockwise transaction client listener */
	BlockwiseTransactionClientListener listener;
	
	/** Whether the request has been sent */
	boolean request_sent=false;


	
	/** Creates a new BlockwiseTransactionClient.
	 * @param coap_provider the CoAP provider
	 * @param req the request message
	 * @param remote_soaddr the socket address of the remote CoAP server
	 * @param listener the listener of this blockwise transaction client */
	public BlockwiseTransactionClient(CoapProvider coap_provider, CoapRequest req, InetSocketAddress remote_soaddr, BlockwiseTransactionClientListener listener) {
		this.coap_provider=coap_provider;
		this.req=req;
		this.remote_soaddr=remote_soaddr;
		this.listener=listener;
	}

	
	/** Sets the maximum block size.
	 * @param client_max_size maximum block size
	 * @return this object */
	public BlockwiseTransactionClient setMaximumBlockSize(int client_max_size) {
		this.client_max_size=client_max_size;
		return this;
	}


	/** Gets the request message.
	 * @return the request message */
	public CoapRequest getRequestMessage() {
		return req;
	}

	
	/** Sends the CoAP request. */
	public void request() {
		if (request_sent) {
			warning("request(): request message already sent");
			return;
		}
		// else
		request_sent=true;
		if (client_max_size>0) req.addOption(new Block2Option(0,false,client_max_size));
		Block1ClientListener this_b1c_listener=new Block1ClientListener() {
			@Override
			public void onReceivedResponse(Block1Client block1_client, CoapResponse resp) {
				processReceivedResponse(block1_client,resp);
			}
			@Override
			public void onBlock1ClientFailure(Block1Client block1_client) {
				processBlock1ClientFailure(block1_client);
			}
		};
		//new Block1Client(coap_provider,req,remote_soaddr,this_b1c_listener).setMaximumBlockSize(client_max_size).request();
		new Block1Client(coap_provider,req,remote_soaddr,client_max_size,this_b1c_listener).request();
	}
	
	
	/** When a new CoAP response message is received.
	 * @param block1_client the blockwise transfer client
	 * @param resp the received CoAP response */
	private void processReceivedResponse(Block1Client block1_client, CoapResponse resp) {
		req.removeOption(CoapOptionNumber.Block1);
		req.setPayload(null);
		Block2ClientListener this_b2c_listener=new Block2ClientListener() {
			@Override
			public void onReceivedResponse(Block2Client block2_client, CoapResponse resp) {
				processReceivedResponse(block2_client,resp);
			}
			@Override
			public void onBlock2ClientFailure(Block2Client block2_client) {
				processBlock2ClientFailure(block2_client);
			}
		};
		new Block2Client(coap_provider,req,resp,this_b2c_listener);
	}

	/** When a RST is received for a Confirmable request or transaction timeout expired.
	 * @param block1_client the block1 client */
	private void processBlock1ClientFailure(Block1Client block1_client) {
		debug("processBlock1ClientFailure(): listener: "+listener);
		if (listener!=null) listener.onTransactionFailure(this);
	}
	
	/** When a new CoAP response message is received.
	 * @param block2_client the blockwise transfer client
	 * @param msg the received CoAP response */
	private void processReceivedResponse(Block2Client block2_client, CoapResponse resp) {
		debug("processReceivedResponse(): listener: "+listener);
		if (listener!=null) listener.onTransactionResponse(this,resp);
		listener=null;
	}

	/** When a RST is received for a Confirmable request or transaction timeout expired.
	 * @param block2_client the block2 client */
	private void processBlock2ClientFailure(Block2Client block2_client) {
		debug("processBlock2ClientFailure(): listener: "+listener);
		if (listener!=null) listener.onTransactionFailure(this);
	}

}
