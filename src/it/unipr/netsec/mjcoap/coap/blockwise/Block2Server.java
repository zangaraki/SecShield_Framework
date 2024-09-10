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
import org.zoolu.util.ByteUtils;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.mjcoap.coap.message.*;
import it.unipr.netsec.mjcoap.coap.option.Block2Option;
import it.unipr.netsec.mjcoap.coap.option.CoapOption;
import it.unipr.netsec.mjcoap.coap.option.CoapOptionNumber;
import it.unipr.netsec.mjcoap.coap.provider.CoapId;
import it.unipr.netsec.mjcoap.coap.provider.CoapProvider;
import it.unipr.netsec.mjcoap.coap.provider.CoapProviderListener;
import it.unipr.netsec.mjcoap.coap.transaction.CoapTransactionServer;


/** Server-side support for blockwise transfers from server to client (RFC 7959).
 */
public class Block2Server {
	
	/** Logs a debug message. */
	private void debug(String str) {
		if (BlockwiseTransactionClient.DEBUG) SystemUtils.log(LoggerLevel.TRACE,getClass(),str);
	}
	
	/** Max server-side block size */
	int server_max_size=0;

	/** CoAP provider */
	CoapProvider coap_provider;

	/** Request */
	CoapRequest req=null;

	/** Composed response */
	CoapResponse resp=null;

	/** CoAP provider listener */
	CoapProviderListener this_cp_listener;

	
	
	/** Creates a new Block2Server. */
	public Block2Server() {
	}


	/** Creates a new Block2Server.
	 * @param server_max_size the maximum size */
	public Block2Server(CoapProvider coap_provider, CoapRequest req, int server_max_size) {
		debug("Block2Server()");
		this.coap_provider=coap_provider;
		this.req=req;
		this.server_max_size=server_max_size;
		
		this_cp_listener=new CoapProviderListener() {
			public void onReceivedMessage(CoapProvider coap_provider, CoapMessage msg) {  processReceivedMessage(coap_provider,msg);  }
		};
		coap_provider.addListener(CoapId.getTransferId(req.getRemoteSoAddress(),req.getMethod(),req.getRequestUriPath()),this_cp_listener);
	}


	/** When a new CoAP message is received. */
	private void processReceivedMessage(CoapProvider coap_provider, CoapMessage msg) {
		debug("processReceivedMessage()");
		if (resp!=null) respond(new CoapRequest(msg),resp);
	}

	
	/** Responds to the request.
	 * @param resp a NON-blockwise response message */
	public void respond(CoapResponse resp) {
		this.resp=resp;
		respond(req,resp);
	}
	
	
	/** Responds to the request.
	 * @param resp a NON-blockwise response message */
	private void respond(CoapRequest req, CoapResponse resp) {
		resp=blockwiseResponse(req,new CoapResponse(resp),server_max_size);
		debug("respond()");
		CoapOption block2_opt=resp.getOption(CoapOptionNumber.Block2);
		if (block2_opt==null || !new Block2Option(block2_opt).moreBlocks()) coap_provider.removeListener(this_cp_listener);
		new CoapTransactionServer(coap_provider,req,null).respond(resp); 
	}
	
	
	/** Makes a response blockwise compatible.
	 * @param req the request message
	 * @param resp a NON-blockwise response message
	 * @return the blockwise compatible response */
	public static CoapResponse blockwiseResponse(CoapRequest req, CoapResponse resp, int server_max_size) {
		byte[] payload=resp.getPayload();
		int seqn=0;
		if (payload!=null) {
			if (req.hasOption(CoapOptionNumber.Block2)) {
				// client max size
				Block2Option req_block2opt=new Block2Option(req.getOption(CoapOptionNumber.Block2));
				int size=req_block2opt.getSize();
				seqn=(int)req_block2opt.getSequenceNumber();
				if (server_max_size>0 && size>server_max_size) {
					size=server_max_size;
					seqn=0;
				}
				int offset=seqn*size;
				boolean more=payload.length>(offset+size);
				payload=ByteUtils.copy(payload,offset,(more)?size:payload.length-offset);
				resp.setPayload(payload);
				resp.addOption(new Block2Option(seqn,more,size));
			}
			else
			if (server_max_size>0) {
				// server max size
				if (payload.length>server_max_size) {
					payload=ByteUtils.copy(payload,0,server_max_size);
					resp.setPayload(payload);
					resp.addOption(new Block2Option(seqn,true,server_max_size));
				}
				else {
					resp.addOption(new Block2Option(seqn,false,server_max_size));
				}
			}
		}
		if (seqn==0 && req.hasOption(CoapOptionNumber.Block1)) {
			resp.addOption(req.getOption(CoapOptionNumber.Block1));
		}
		return resp;
	}

}
