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
import java.util.Vector;

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.mjcoap.coap.message.*;
import it.unipr.netsec.mjcoap.coap.option.Block2Option;
import it.unipr.netsec.mjcoap.coap.option.CoapOptionNumber;
import it.unipr.netsec.mjcoap.coap.provider.CoapProvider;
import it.unipr.netsec.mjcoap.coap.transaction.CoapTransactionClient;
import it.unipr.netsec.mjcoap.coap.transaction.CoapTransactionClientListener;


/** Client-side support for blockwise transfers from server to client (RFC 7959).
 * <p>
 * It takes a request/response message pair and it handles the reliable transfers of possible response slices.
 * If the body of the original response exceeds the maximum block size from server to client,
 * the body is sliced by the server in blocks that are sent as payload of two or more response messages (blockwise transfer).
 * <p>
 * When the last slice is successfully received, the callback method {@link Block2ClientListener#onReceivedResponse(Block2Client, CoapResponse)}
 * is called.
 */
class Block2Client {
	
	/** Logs a debug message. */
	private void debug(String str) {
		if (BlockwiseTransactionClient.DEBUG) SystemUtils.log(LoggerLevel.TRACE,getClass(),str);
	}

	/** Max client-side block size */
	int client_max_size=0;

	/** CoapProvider */
	CoapProvider coap_provider;

	/** Request message */
	CoapRequest req;

	/** Remote socket address */
	InetSocketAddress remote_soaddr;

	/** Sequence number of received bytes */
	long seqn=0;
	
	/** Block buffer */
	Vector<byte[]> block_buffer=new Vector<byte[]>();
	
	/** CoAP transaction client*/
	CoapTransactionClientListener this_tc_listener;
 
	/** Block2Client listener */
	Block2ClientListener listener;
	
	/** Whether the request has been sent */
	boolean is_sent=false;



	/** Creates a new Block2Client.
	 * @param coap_provider the CoAP provider
	 * @param req the first request message
	 * @param remote_soaddr the socket address of the remote CoAP server
	 * @param b2c_listener the listener of this blockwise transfer client */
	/*public Block2Client(CoapProvider coap_provider, CoapRequest req, InetSocketAddress remote_soaddr, Block2ClientListener listener) {
		init(coap_provider,req,remote_soaddr,listener);
	}*/


	/** Creates a new Block2Client.
	 * @param coap_provider the CoAP provider
	 * @param req the first request message
	 * @param resp the first response message
	 * @param b2c_listener the listener of this blockwise transfer client */
	public Block2Client(CoapProvider coap_provider, CoapRequest req, CoapResponse resp, Block2ClientListener listener) {
		init(coap_provider,req,resp.getRemoteSoAddress(),listener);
		processTransactionResponse(null,resp);
	}
  
	
	
	/** Initializes the Block2Client.
	 * @param coap_provider the CoAP provider
	 * @param req the first request message
	 * @param remote_soaddr the socket address of the remote CoAP server
	 * @param b2c_listener the listener of this blockwise transfer client */
	private void init(CoapProvider coap_provider, CoapRequest req, InetSocketAddress remote_soaddr, Block2ClientListener listener) {
		this.coap_provider=coap_provider;
		this.req=req;
		this.remote_soaddr=remote_soaddr;
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
	 * @param client_max_size
	 * @return this object */
	public Block2Client setMaximumBlockSize(int client_max_size) {
		this.client_max_size=client_max_size;
		return this;
	}


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
		if (client_max_size>0) req.addOption(new Block2Option(0,false,client_max_size));
		debug("request()");
		new CoapTransactionClient(coap_provider,req,remote_soaddr,this_tc_listener).request();
	}


	/** When a CoAP response is received for the pending request. */
	private void processTransactionResponse(CoapTransactionClient tc, CoapResponse resp) {
		debug("processTransactionResponse()");
		if (!resp.hasOption(CoapOptionNumber.Block2)) {
			debug("processTransactionResponse(): passed to listener: "+listener);
			if (listener!=null) listener.onReceivedResponse(this,resp);
		}
		else {
			debug("processTransactionResponse(): Block2 option found");
			byte[] block=resp.getPayload();
			if (block==null || block.length==0) {
				debug("processTransactionResponse(): passed to listener: "+listener);
				if (listener!=null) listener.onReceivedResponse(this,resp);				
			}
			else {
				Block2Option block2_opt=new Block2Option(resp.getOption(CoapOptionNumber.Block2));
				long block2_seqn=block2_opt.getSequenceNumber();
				int size=block2_opt.getSize();
				boolean more=block2_opt.moreBlocks();
				// update the receiver block buffer
				if ((block2_seqn*size)!=seqn) {
					debug("processTransactionResponse(): seqn mismatch: restart with seqn=0");
					// re-request the first missing block
					req.setMessageId(CoapMessage.pickMessageId());
					req.setToken(CoapMessage.pickToken());
					req.setOption(new Block2Option(seqn=0,false,size));
					new CoapTransactionClient(coap_provider,req,remote_soaddr,this_tc_listener).request();
				}
				else {
					// update the receiver buffer
					block_buffer.addElement(block);
					seqn+=block.length;
					if (more) {
						debug("processTransactionResponse(): request next block");
						// request the next block
						req.setMessageId(CoapMessage.pickMessageId());
						req.setToken(CoapMessage.pickToken());
						req.setOption(new Block2Option(seqn/size,false,size));
						new CoapTransactionClient(coap_provider,req,remote_soaddr,this_tc_listener).request();
					}
					else {
						debug("processTransactionResponse(): it was the last block: recompose the response");
						// compose the body and pass it to the user
						byte[] body=new byte[(int)seqn];
						int index=0;
						for (int i=0; i<block_buffer.size(); i++) {
							byte[] block_i=(byte[])block_buffer.elementAt(i);
							for (int k=0; k<block_i.length; k++) body[index++]=block_i[k];
						}
						resp.removeOption(CoapOptionNumber.Block2);
						resp.setPayload(body);
						if (listener!=null) listener.onReceivedResponse(this,resp);
					}
				}
			}
		}
	}


	/** When a RST is received for a Confirmable request or transaction timeout expired. */
	private void processTransactionFailure(CoapTransactionClient tc) {
		debug("processTransactionFailure()");
		if (listener!=null) listener.onBlock2ClientFailure(this);
	}

}
