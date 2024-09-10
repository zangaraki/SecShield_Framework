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


import MyProject.CoapMessage;
import java.net.InetSocketAddress;

import org.zoolu.util.ByteUtils;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.mjcoap.coap.message.*;
import it.unipr.netsec.mjcoap.coap.option.Block1Option;
import it.unipr.netsec.mjcoap.coap.option.Block2Option;
import it.unipr.netsec.mjcoap.coap.option.CoapOptionNumber;
import it.unipr.netsec.mjcoap.coap.provider.CoapProvider;
import it.unipr.netsec.mjcoap.coap.transaction.CoapTransactionClient;
import it.unipr.netsec.mjcoap.coap.transaction.CoapTransactionClientListener;


/** Client-side support for blockwise transfers from client to server (RFC 7959).
 * <p>
 * It takes a request message and it reliably transfers the message.
 * If the body of the message exceeds the maximum block size from client to server,
 * the body is sliced in blocks that are sent as payload of two or more request messages (blockwise transfer).
 * <p>
 * When the last slice is successfully sent and acknowledged, the callback method {@link Block1ClientListener#onReceivedResponse(Block1Client, CoapResponse)}
 * is called.
 */
class Block1Client {
	
	/** Logs a debug message. */
	private void debug(String str) {
		if (BlockwiseTransactionClient.DEBUG) SystemUtils.log(LoggerLevel.TRACE,getClass(),str);
	}

	/** Max client-side block size */
	int client_max_size=0;

	/** CoAP provider */
	CoapProvider coap_provider;

	/** Remote socket address */
	InetSocketAddress remote_soaddr;

	/** Request message */
	CoapRequest req;

	/** Sequence number of received bytes */
	long seqn=0;
	
	/** Request body */
	byte[] req_body;

	/** CoAP transaction client listener */
	CoapTransactionClientListener this_tc_listener;
 
	/** Block2Client listener */
	Block1ClientListener listener;
	
	/** Whether the request has been sent */
	boolean is_sent=false;



	/** Creates a new Block1Client.
	 * @param coap_provider the CoAP provider
	 * @param req the request message
	 * @param remote_soaddr the socket address of the remote CoAP server
	 * @param b2c_listener the listener of this blockwise transfer client */
	public Block1Client(CoapProvider coap_provider, CoapRequest req, InetSocketAddress remote_soaddr, int client_max_size, Block1ClientListener listener) {
		this.coap_provider=coap_provider;
		this.req=req;
		req_body=req.getPayload();
		this.remote_soaddr=remote_soaddr;
		this.client_max_size=client_max_size;
		this.listener=listener;
		this_tc_listener=new CoapTransactionClientListener() {
			public void onTransactionResponse(CoapTransactionClient tc, CoapResponse resp) {
				processTransactionResponse(tc,resp);
			}
			public void onTransactionFailure(CoapTransactionClient tc) {
				processTransactionFailure(tc);
			}
		};
	}


	/** Sets the maximum block size.
	 * @param client_max_size */
	/*public void setMaximumBlockSize(int client_max_size) {
		this.client_max_size=client_max_size;
	}*/


	/** Gets the request message.
	 * @return the request message */
	public CoapMessage getRequestMessage() {
		return req;
	}

  
	/** Sends the CoAP request. */
	public void request() {
		if (is_sent) return;
		// else
		is_sent=true;
		if (client_max_size>0) {
			if (req_body!=null && req_body.length>0) {
				if (req_body.length>client_max_size) {
					byte[] block_0=ByteUtils.copy(req_body,0,client_max_size);
					req.setPayload(block_0);
					req.addOption(new Block1Option(0,true,client_max_size));
				}
				else req.addOption(new Block1Option(0,false,client_max_size));				
			}
		}
		new CoapTransactionClient(coap_provider,req,remote_soaddr,this_tc_listener).request();
	}


	/** When a CoAP response is received for the pending request. */
	private void processTransactionResponse(CoapTransactionClient tc, CoapResponse resp) {
		debug("processTransactionResponse()");
		if (!resp.hasOption(CoapOptionNumber.Block1)) {
			debug("processTransactionResponse(): no Block1 option");
			debug("processTransactionResponse(): passed to listener: "+listener);
			if (listener!=null) listener.onReceivedResponse(this,resp);
		}
		else
		if (req_body==null || req_body.length==0) {
			// Note: it should never arrive here, since Block1 is not added in case of empty body in the request..
			debug("processTransactionResponse(): no request body");
			debug("processTransactionResponse(): passed to listener: "+listener);
			if (listener!=null) listener.onReceivedResponse(this,resp);
		}
		else {
			Block2Option block1_opt=new Block2Option(resp.getOption(CoapOptionNumber.Block1));
			long block1_seqn=block1_opt.getSequenceNumber();
			int block1_size=block1_opt.getSize();
			boolean more=block1_opt.moreBlocks();
			debug("processTransactionResponse(): block1_seqn="+block1_seqn+", more="+more+", block1_size="+block1_size);
			if (block1_size*block1_seqn==seqn) {
				debug("processTransactionResponse(): seqn number match");
				seqn+=block1_size;
				if (seqn+block1_size<req_body.length) {
					debug("processTransactionResponse(): two or more blocks to be sent");
					byte[] block_i=ByteUtils.copy(req_body,(int)seqn,block1_size);
					req=new CoapRequest(req);
					req.setMessageId(CoapMessage.pickMessageId());
					req.setPayload(block_i);
					req.setOption(new Block1Option((int)(seqn/block1_size),true,block1_size));
					new CoapTransactionClient(coap_provider,req,remote_soaddr,this_tc_listener).request();
				}
				else
				if (seqn<req_body.length) {
					debug("processTransactionResponse(): only one more block to be sent ("+(req_body.length-(int)seqn)+"B)");
					byte[] block_i=ByteUtils.copy(req_body,(int)seqn,req_body.length-(int)seqn);
					req=new CoapRequest(req);
					req.setMessageId(CoapMessage.pickMessageId());
					req.setPayload(block_i);
					req.setOption(new Block1Option((int)(seqn/block1_size),false,block1_size));
					new CoapTransactionClient(coap_provider,req,remote_soaddr,this_tc_listener).request();
				}
				else {
					debug("processTransactionResponse(): last block has been successfully acknowledged");
					if (listener!=null) listener.onReceivedResponse(this,resp);
				}
			}
			else {
				// sequence number error
				debug("processTransactionResponse(): sequence number mismatching");
			}
		}
	}


	/** When a RST is received for a Confirmable request or transaction timeout expired. */
	private void processTransactionFailure(CoapTransactionClient tc) {
		debug("processTransactionFailure()");
		if (listener!=null) listener.onBlock1ClientFailure(this);
	}

}
