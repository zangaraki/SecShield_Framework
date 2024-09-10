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

package it.unipr.netsec.mjcoap.coap.server;


import MyProject.CoapMessage;
import java.net.SocketException;
import java.util.Hashtable;

import it.unipr.netsec.mjcoap.coap.blockwise.BlockwiseTransactionServer;
import it.unipr.netsec.mjcoap.coap.blockwise.BlockwiseTransactionServerListener;
import it.unipr.netsec.mjcoap.coap.message.*;
import it.unipr.netsec.mjcoap.coap.observe.ObserveTransactionServer;
import it.unipr.netsec.mjcoap.coap.observe.ObserveTransactionServerListener;
import it.unipr.netsec.mjcoap.coap.provider.*;
import it.unipr.netsec.mjcoap.coap.transaction.CoapTransactionServer;


/** Abstract stateful CoAP server.
 * It handles CoAP GET, PUT, and DELETE requests statefully, automatically handling request/response retransmissions.
 * <p>
 * It supports resource observation (RFC 7641) and blockwise transfer (RFC 7959).
 * <p>
 * An actual CoAP server must implement one (or more) of the following methods:
 * <ul>
 * <li> {@link #handleGetRequest(CoapRequest)} - processes a new incoming GET request,</li>
 * <li> {@link #handlePostRequest(CoapRequest)} - processes a new incoming POST request,</li>
 * <li> {@link #handlePutRequest(CoapRequest)} - processes a new incoming PUT request,</li>
 * <li> {@link #handleDeleteRequest(CoapRequest)} - processes a new incoming DELTE request,</li>
 * <li> {@link #handleObserveRequest(CoapRequest)} - processes a new incoming observe request,</li>
 * <li> {@link #handleObserveTerminated(CoapRequest)} - processes an observe termination.</li>
 * </ul>
 * <p>
 * Please see the source code of {@link CoapServer} as example of use.
 */
public abstract class AbstractCoapServer {

	/** CoAP messaging layer */
	protected CoapProvider coap_provider;

	/** Server-side CoAP observe listener */
	ObserveTransactionServerListener this_os_listener;
	
	/** Maximum block size */
	int max_block_size=0;

	/** Table of transaction servers */
	Hashtable<CoapRequest,BlockwiseTransactionServer> transaction_servers=new Hashtable<CoapRequest,BlockwiseTransactionServer>();

	/** Table of observe servers */
	Hashtable<CoapRequest,ObserveTransactionServer> observe_servers=new Hashtable<CoapRequest,ObserveTransactionServer>();

	

	/** Creates a new CoAP server. */
	public AbstractCoapServer() throws SocketException {
		init(-1);
	}


	/** Creates a new CoAP server.
	 * @param local_port CoAP UDP port */
	public AbstractCoapServer(int local_port) throws SocketException {
		init(local_port);
	}


	/** Inits the CoAP server.
	 * @param local_port CoAP UDP port */
	private void init(int local_port) throws SocketException {
		if (local_port<0) local_port=CoapProvider.DEFAUL_PORT;

		this_os_listener=new ObserveTransactionServerListener() {	
			@Override
			public void onObserveServerTerminated(ObserveTransactionServer observe_server) {
				CoapRequest req=observe_server.getRequestMessage();
				observe_servers.remove(req);
				handleObserveTerminated(req);
			}
		};
				
		CoapProviderListener this_cp_listener=new CoapProviderListener() {
			@Override
			public void onReceivedMessage(CoapProvider cp, CoapMessage msg) {
				CoapRequest req=new CoapRequest(msg);
				BlockwiseTransactionServerListener this_ts_listener=new BlockwiseTransactionServerListener() {
					@Override
					public void onReceivedRequest(BlockwiseTransactionServer ts, CoapRequest req) {
						if (req.isGET() && req.hasObserveRegister()) {
							handleObserveRequest(req);
						}
						else {
							transaction_servers.put(req,ts);
							if (req.isGET()) handleGetRequest(req);
							else
							if (req.isPOST()) handlePostRequest(req);
							else
						    if (req.isPUT()) handlePutRequest(req);
						    else
							if (req.isDELETE()) handleDeleteRequest(req);
						    else
							respond(req,CoapResponseCode._4_05_Method_Not_Allowed);
						}
					}
					@Override
					public void onTransactionFailure(CoapTransactionServer ts) {
						// doing something?
					}	
				};
				new BlockwiseTransactionServer(coap_provider,req,max_block_size,this_ts_listener);
			}
		};
		coap_provider=new CoapProvider(local_port);
		coap_provider.addListener(CoapId.REQUEST,this_cp_listener);
	}

	/** Sets the maximum block size.
	 * @param max_block_size the maximum block size */
	public void setMaximumBlockSize(int max_block_size) {
		this.max_block_size=max_block_size;
	}


	/** Processes a received GET request.
	 * @param req the received GET request message */
	protected void handleGetRequest(CoapRequest req) {
		respond(req,CoapResponseCode._4_05_Method_Not_Allowed);
	}


	/** Processes a received POST request.
	 * @param req the received POST request message */
	protected void handlePostRequest(CoapRequest req) {
		respond(req,CoapResponseCode._4_05_Method_Not_Allowed);
	}


	/** Processes a received PUT request.
	 * @param req the received PUT request message */
	protected void handlePutRequest(CoapRequest req) {
		respond(req,CoapResponseCode._4_05_Method_Not_Allowed);
	}


	/** Processes a received DELETE request.
	 * @param req the received DELETE request message */
	protected void handleDeleteRequest(CoapRequest req) {
		respond(req,CoapResponseCode._4_05_Method_Not_Allowed);
	}


	/** When a CoAP observe request is received.
	  * @param req the received CoAP observe request */
	protected void handleObserveRequest(CoapRequest req) {
		respond(req,CoapResponseCode._4_05_Method_Not_Allowed);
	}


	/** When a CoAP observation terminated.
	  * @param req the original observe request message that requested the service */
	protected void handleObserveTerminated(CoapRequest req) {
	}


	/** Responds to a pending request.
	 * @param req a pending request message
	 * @param response_code the response code
	 * @return <i>false</i> if no pending request has been found */
	public boolean respond(CoapRequest req, CoapResponseCode response_code) {
	    return respond(req,response_code,-1,null);		
	}

		
	/** Responds to a pending request.
	 * @param req a pending request message
	 * @param response_code the response code
	 * @param format response payload format
	 * @param payload response payload 
	 * @return <i>false</i> if no pending request has been found */
	public boolean respond(CoapRequest req, CoapResponseCode response_code, int format, byte[] payload) {
	    CoapResponse resp=CoapMessageFactory.createResponse(req,response_code);	
	    if (format>=0) resp.setContentFormat(format);
	    if (payload!=null) resp.setPayload(payload);
	    return respond(req,resp);		
	}

		
	/** Responds to a pending request.
	 * @param req a pending request message
	 * @param resp the response message to be sent 
	 * @return <i>false</i> if no pending request has been found */
	public boolean respond(CoapRequest req, CoapResponse resp) {
		if (req.isGET() && req.hasObserveRegister()) {
			if (!observe_servers.containsKey(req)) observe_servers.put(req,new ObserveTransactionServer(coap_provider,req,this_os_listener));
			ObserveTransactionServer os=observe_servers.get(req);
			os.notify(resp);
			return true;
		}
		else {
			BlockwiseTransactionServer ts=transaction_servers.get(req);
			if (ts!=null) {
				ts.respond(resp);
				transaction_servers.remove(req);
				return true;
			}
			else return false;
		}
	}

	
	/** Stops the server. */
	public void halt() {
		coap_provider.halt();
	}

}
