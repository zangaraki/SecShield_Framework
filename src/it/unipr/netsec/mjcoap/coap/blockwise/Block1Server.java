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
import it.unipr.netsec.mjcoap.coap.option.Block1Option;
import it.unipr.netsec.mjcoap.coap.option.CoapOptionNumber;
import it.unipr.netsec.mjcoap.coap.provider.*;


/** Server-side support for blockwise transfers from client to server (RFC 7959).
 * <p>
 * It takes a request message and it handles the reliable transfers of possible successive request slices (blockwise transfer).
 * <p>
 * When all request slices are successfully received and acknowledged, the callback method {@link Block1ClientListener#onReceivedResponse(Block1Client, CoapResponse)}
 * is called.
 */
class Block1Server {
	
	/** Logs a debug message. */
	private void debug(String str) {
		if (BlockwiseTransactionClient.DEBUG) SystemUtils.log(LoggerLevel.TRACE,getClass(),str);
	}
	
	/** Max server-side block size */
	int server_max_size=0;

	/** CoAP provider */
	CoapProvider coap_provider;

	/** Request */
	CoapRequest req;

	/** Sequence number of received bytes */
	//long seqn=0;
	
	/** Block buffer */
	BlockBuffer block_buffer=null;

	/** Current block size */
	int current_block_size=-1;

	/** Last block sequence number */
	int last_block_seqn=-1;

	/** CoAP provider listener */
	CoapProviderListener this_cp_listener;
	
	/** Block2Client listener */
	Block1ServerListener listener;

	
	/** Creates a new Block2Server.
	 * @param coap_provider the CoAP provider
	 * @param req the request message
	 * @param server_max_size the maximum size
	 * @param listener blockwise server listener */
	public Block1Server(CoapProvider coap_provider, CoapRequest req, int server_max_size, Block1ServerListener listener) {
		debug("Block1Server()");
		this.coap_provider=coap_provider;
		this.req=req;
		this.server_max_size=server_max_size;
		this.listener=listener;
		this_cp_listener=new CoapProviderListener() {
			public void onReceivedMessage(CoapProvider coap_provider, CoapMessage msg) {  processReceivedMessage(coap_provider,msg);  }
		};
		coap_provider.addListener(CoapId.getTransferId(req.getRemoteSoAddress(),req.getMethod(),req.getRequestUriPath()),this_cp_listener);
		processReceivedMessage(coap_provider,req);
	}


	/** When a new CoAP message is received. */
	private void processReceivedMessage(CoapProvider coap_provider, CoapMessage msg) {
		debug("processReceivedMessage()");
		if (msg.isRequest()) {
			CoapRequest req=new CoapRequest(msg);
			if (!req.hasOption(CoapOptionNumber.Block1)) {
				debug("processReceivedMessage(): no Block1 option");
				coap_provider.removeListener(this_cp_listener);
				debug("processReceivedMessage(): passed to listener: "+listener);
				if (listener!=null) listener.onReceivedRequest(this,req);
			}
			else {
				Block1Option block1_opt=new Block1Option(req.getOption(CoapOptionNumber.Block1));
				int block1_seqn=(int)block1_opt.getSequenceNumber();
				int block1_size=block1_opt.getSize();
				byte[] block=req.getPayload();
				boolean more=block1_opt.moreBlocks();
				debug("processReceivedMessage(): block1_seqn="+block1_seqn+", more="+more+", block1_size="+block1_size);
				if (server_max_size!=0 && server_max_size<block1_size) {
					debug("processReceivedMessage(): small server_max_size="+server_max_size);
					block1_size=server_max_size;
					debug("processReceivedMessage(): new block buffer");
					block_buffer=new BlockBuffer();
					current_block_size=block1_size;
					last_block_seqn=-1;
					if (block1_seqn==0) {
						block=ByteUtils.copy(block,0,block1_size);
						debug("processReceivedMessage(): add block 0");
						block_buffer.setBlockAt(block,0);
					}
				}
				else {
					if (block_buffer==null || current_block_size!=block1_size) {
						debug("processReceivedMessage(): new block buffer");
						block_buffer=new BlockBuffer();
						current_block_size=block1_size;
					}
					debug("processReceivedMessage(): set block "+block1_seqn);
					if (block!=null) block_buffer.setBlockAt(block,block1_seqn);
					if (!more) last_block_seqn=block1_seqn;
				}
				if (block1_seqn!=last_block_seqn || !block_buffer.isFull()) {
					debug("processReceivedMessage(): buffer is not full");
					CoapResponse resp=CoapMessageFactory.createPiggyBackedResponse(req,CoapResponseCode._2_31_Continue);
					resp.addOption(new Block1Option(block1_seqn,true,block1_size));
					debug("processReceivedMessage(): send biggy-backed response 2.31 Continue");
					coap_provider.send(resp,req.getRemoteSoAddress());
				}
				else {
					debug("processReceivedMessage(): buffer is full");
					// compose the body and pass it to the user
					byte[] body=block_buffer.getBytes();
					//req.removeOption(CoapOptionNumber.Block1);
					req.setPayload(body);
					debug("processReceivedMessage(): request has been re-composed");
					// remove this coap provider listener
					coap_provider.removeListener(this_cp_listener);
					if (listener!=null) listener.onReceivedRequest(this,req);
					listener=null;
				}
			}
		}
	}

}
