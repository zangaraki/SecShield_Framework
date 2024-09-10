/*
 * Copyright (c) 2018 NetSec Lab - University of Parma
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

package it.unipr.netsec.mjcoap.coap.transaction;


import java.net.InetSocketAddress;

import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import MyProject.CoapMessage;
import it.unipr.netsec.mjcoap.coap.message.CoapRequest;
import it.unipr.netsec.mjcoap.coap.message.CoapResponse;
import it.unipr.netsec.mjcoap.coap.provider.CoapId;
import it.unipr.netsec.mjcoap.coap.provider.CoapProvider;
import it.unipr.netsec.mjcoap.coap.provider.CoapProviderListener;
import it.unipr.netsec.mjcoap.coap.transmission.CoapReliableReception;
import it.unipr.netsec.mjcoap.coap.transmission.CoapReliableTransmission;
import it.unipr.netsec.mjcoap.coap.transmission.CoapReliableTransmissionListener;


/** CoAP transaction client. It handles a client-side CoAP transaction.
  * <p>
  * A transaction client is created by specifying:
  * <ul>
  * <li>the CoAP provider, used to send the request and receive the response,</li>
  * <li>the request message,</li>
  * <li>the destination socket address,</li>
  * <li>the transaction client listener.</li>
  * </ul>
  * The request message is actually sent when the method {@link #request()} is called.
  * If the transaction client receives a response message within the transaction timeout,
  * the response is passed to the transaction client listener through the method {@link CoapTransactionClientListener#onTransactionResponse(CoapTransactionClient, CoapResponse)},
  * otherwise, in case the timeout expires, the method {@link CoapTransactionClientListener#onTransactionFailure(CoapTransactionClient)} is fired;
  * only one of this two methods will be called, only one time.
  * <p>
  * The transaction client automatically handles request retransmissions and duplicated response receptions.
  */
public class CoapTransactionClient {
	
	/** Logs a warning message.
	  * @param str the message to be logged */
	private void warning(String str) {
		SystemUtils.log(LoggerLevel.WARNING,getClass(),str);
	}

	/** CoapProvider */
	CoapProvider coap_provider;

	/** Request message */
	CoapRequest req;

	/** Remote socket address */
	InetSocketAddress remote_soaddr;

	/** CoapTransactionClient listener */
	CoapTransactionClientListener tc_listener;

	/** Request reliable transmission */
	CoapReliableTransmission reliable_transmission=null;
	
	/** Whether the request has been sent */
	boolean request_sent=false;
	
	

	/** Creates a new CoapTransactionClient.
	 * @param coap_provider the CoAP provider
	 * @param req the request message
	 * @param remote_soaddr the socket address of the remote CoAP server
	 * @param tc_listener the listener of this transaction client */
	public CoapTransactionClient(CoapProvider coap_provider, CoapRequest req, InetSocketAddress remote_soaddr, CoapTransactionClientListener tc_listener) {
		this.coap_provider=coap_provider;
		this.req=req;
		this.remote_soaddr=remote_soaddr;
		this.tc_listener=tc_listener;
	}


	/** Gets the request message.
	 * @return the request message */
	public CoapRequest getRequestMessage() {
		return req;
	}

	
	/** Starts the transaction by sending the CoAP request. */
	public void request() {
		if (request_sent) {
			warning("request(): request message already sent");
			return;
		}
		// else
		request_sent=true;
		CoapProviderListener this_cp_listener=new CoapProviderListener() {
			public void onReceivedMessage(CoapProvider coap_provider, CoapMessage msg) {  processReceivedMessage(coap_provider,msg);  }
		};
		coap_provider.addListener(CoapId.getTransactionId(remote_soaddr,req.getToken()),this_cp_listener);
		if (req.isCON()) {
			// req=CON,Request
			CoapReliableTransmissionListener this_rt_listener=new CoapReliableTransmissionListener() {
				public void onTransmissionAcknowledgement(CoapReliableTransmission reliable_transmission, CoapMessage ack) {  processTransmissionAcknowledgement(reliable_transmission,ack);  }
				public void onTransmissionReject(CoapReliableTransmission reliable_transmission, CoapMessage rst) {  processTransmissionReject(reliable_transmission,rst);  }
				public void onTransmissionTimeout(CoapReliableTransmission reliable_transmission) {  processTransmissionTimeout(reliable_transmission);  }
			};
			reliable_transmission=new CoapReliableTransmission(coap_provider,remote_soaddr,this_rt_listener);
			reliable_transmission.send(req);
		}
		else {
			// req=NON,Request
			coap_provider.send(req,remote_soaddr);
		}
	}


	/** When a new CoAP message is received.
	 * @param coap_provider the CoAP provider
	 * @param msg the received message */
	private void processReceivedMessage(CoapProvider coap_provider, CoapMessage msg) {
		if (msg.isResponse()) {
			CoapResponse resp=new CoapResponse(msg);
			// reliable_transmission is not automatically terminated in case of separate (CON and NON) response
			if (reliable_transmission!=null) reliable_transmission.terminate();
			if (resp.isCON()) {
				// resp=CON,Response
				new CoapReliableReception(coap_provider,resp);
			}
			coap_provider.removeListener(CoapId.getTransactionId(remote_soaddr,resp.getToken()));
			if (tc_listener!=null) tc_listener.onTransactionResponse(this,resp);
		}
	}

	
	/** When a new CoAP message is received.
	* @param coap_provider the CoAP provider
	* @param msg the received message */
	/*private void processReceivedResponseRetransmission(CoapProvider coap_provider, CoapMessage msg) {
		if (msg.isResponse()) {
			if (msg.isCON()) {
				// resp=CON,Response (retransmission)
			}
		}
	}*/

	
	/** When ACK is received confirming the reception of the request.
	* @param reliable_transmission the reliable transmission
	* @param ack the received message */
	private void processTransmissionAcknowledgement(CoapReliableTransmission reliable_transmission, CoapMessage ack) {
		if (ack.isResponse()) {
			// piggybacked response
			processReceivedMessage(coap_provider,ack);
		}
	}


	/** When RST is received confirming the reception of the request.
	* @param reliable_transmission the reliable transmission
	* @param rst the received message */
	private void processTransmissionReject(CoapReliableTransmission reliable_transmission, CoapMessage rst) {
		if (tc_listener!=null) tc_listener.onTransactionFailure(this);
	}


	/** When maximum request retransmission has been reached without receiving any ACK (or RST).
	* @param reliable_transmission the reliable transmission */
	private void processTransmissionTimeout(CoapReliableTransmission reliable_transmission) {
		if (tc_listener!=null) tc_listener.onTransactionFailure(this);
	}
	
}
