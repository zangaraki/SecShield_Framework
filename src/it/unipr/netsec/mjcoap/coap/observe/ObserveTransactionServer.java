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

package it.unipr.netsec.mjcoap.coap.observe;


import MyProject.CoapMessage;
import java.net.InetSocketAddress;

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.mjcoap.coap.blockwise.Block2Server;
import it.unipr.netsec.mjcoap.coap.message.*;
import it.unipr.netsec.mjcoap.coap.option.CoapOptionNumber;
import it.unipr.netsec.mjcoap.coap.provider.CoapId;
import it.unipr.netsec.mjcoap.coap.provider.CoapProvider;
import it.unipr.netsec.mjcoap.coap.provider.CoapProviderListener;
import it.unipr.netsec.mjcoap.coap.transaction.CoapTransactionServer;
import it.unipr.netsec.mjcoap.coap.transmission.CoapReliableTransmission;
import it.unipr.netsec.mjcoap.coap.transmission.CoapReliableTransmissionListener;


/** A CoAP observe server is a CoAP server that notifies resource changes to a given observer.
 * According to the well-known observer design pattern, the observe server is the "subject"
 * where components (called "observers") register at.
 * <p>
 * It implements the observer model according to the RFC 7641 "Observing Resources in CoAP".
 */
public class ObserveTransactionServer {
	
	/** Debug mode */
	static boolean DEBUG=true;

	/** Logs a debug message. */
	private void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,getClass(),str);
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
	
	/** Register request message */
	CoapRequest req;

	/** Sequence number of the last notify */
	int seqn=0;

	/** Last response message  */
	CoapResponse resp;
	
	/** This CoAP provider listener */
	CoapProviderListener this_cp_listener;

	/** This reliable transmission listener */
	CoapReliableTransmissionListener this_rt_listener;
	
	/** Observe server listener */
	ObserveTransactionServerListener listener;
	
	/** Whether the response has been sent */
	boolean response_sent=false;
	
	
	/** Creates a new CoAP observe server.
	 * @param coap_provider the CoAP provider
	 * @param req the observe request sent by the remote observer
	 * @param listener the listener of the observe server (or <i>null</i>) */
	public ObserveTransactionServer(CoapProvider coap_provider, CoapRequest req, ObserveTransactionServerListener listener) {
		debug("ObserveTransactionServer()");
		this.coap_provider=coap_provider;
		this.req=req;
		this.listener=listener;
		this_rt_listener=new CoapReliableTransmissionListener() {
			@Override
			public void onTransmissionAcknowledgement(CoapReliableTransmission reliable_transmission, CoapMessage ack) {
				// do nothing
			}
			@Override
			public void onTransmissionReject(CoapReliableTransmission reliable_transmission, CoapMessage rst) {
				terminate();
			}
			@Override
			public void onTransmissionTimeout(CoapReliableTransmission reliable_transmission) {
				terminate();
			}    
		};
		
		this_cp_listener=new CoapProviderListener() {
			@Override
			public void onReceivedMessage(CoapProvider coap_provider, CoapMessage msg) {
				processReceivedMessage(coap_provider,msg);
			}
		};
		coap_provider.addListener(CoapId.getTransferId(req.getRemoteSoAddress(),CoapRequestMethod.GET,req.getRequestUriPath()),this_cp_listener);
	}

	
	/** Gets the socket address of the remote observer.
	 * @return the socket address */
	public InetSocketAddress getRemoteSocketAddress() {
		return req.getRemoteSoAddress();
	}

	
	/** Gets the observe request message.
	 * @return the request */
	public CoapRequest getRequestMessage() {
		return req;
	}

	
	private void processReceivedMessage(CoapProvider coap_provider, CoapMessage msg) {
		debug("processReceivedMessage()");
		if (msg.isRequest()) {
			CoapRequest req=new CoapRequest(msg);
			if (req.isGET() && req.hasObserveDeregister() && resp!=null) {
				debug("processReceivedMessage(): cancel");
				resp.setCode(CoapResponseCode._2_05_Content.getCode());
				resp.removeOption(CoapOptionNumber.Observe);
				new CoapTransactionServer(coap_provider,req,null).respond(resp);
				terminate();
			}
		}
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

	
	/** Notifies a new resource state.
	 * @param state the new state to be notified */
	/*public void notifyChange(byte[] state) {
		notify(-1,state,false);
	}*/

	
	/** Notifies a new resource state.
	 * @param format the format of the state representation (or <i>null</i>)
	 * @param state the new state to be notified */
	/*public void notifyChange(int format, byte[] state) {
		notify(format,state,false);
	}*/

	
	/** Notifies a new resource state.
	 * @param format the format of the state representation (or <i>-1</i>)
	 * @param state the new state to be notified
	 * @param confirmable whether the notify should be sent in confirmable way */
	public void notify(int format, byte[] state, boolean confirmable) {
		CoapResponse resp;
		if (state!=null) {
			resp=CoapMessageFactory.createResponse(req,CoapResponseCode._2_04_Changed);
			resp.setPayload(format,state);
			if (confirmable) resp.setType(CoapMessageType.CON); else resp.setType(CoapMessageType.NON);
			
		}
		else {
			resp=CoapMessageFactory.createResponse(req,CoapResponseCode._4_04_Not_Found);
			if (confirmable) resp.setType(CoapMessageType.CON); else resp.setType(CoapMessageType.NON);
		}
		notify(resp);
	}

	
	/** Notifies a new resource state.
	 * @param resp the message notifying the new resource state */
	public void notify(CoapResponse resp) {
		debug("notify()");
		this.resp=resp;
		CoapResponseCode response_code=resp.getResponseCode();
		if (response_code.isSuccess()) {
			seqn=(seqn+1)&0xFFFFFF;
			resp.setObserveSequenceNumber(seqn);
			sendNotify(resp);
		}
		else {
			sendNotify(resp);
			terminate();
		}
	}

	
	/** Sends a notify message.
	 * @param resp the response message to be sent */
	private void sendNotify(CoapResponse resp) {
		//if (resp.isCON()) new Block2Server(coap_provider,req,server_max_size).respond(resp);
		if (resp.isCON()) new CoapReliableTransmission(coap_provider,req.getRemoteSoAddress(),this_rt_listener).send(resp);
		else coap_provider.send(resp,req.getRemoteSoAddress());
	}


	/** Terminates. */
	private void terminate() {
		debug("terminate()");
		coap_provider.removeListener(this_cp_listener);
		if (listener!=null) listener.onObserveServerTerminated(this);
	}

}
