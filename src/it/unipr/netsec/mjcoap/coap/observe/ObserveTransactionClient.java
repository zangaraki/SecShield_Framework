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
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;
import org.zoolu.util.Logger;

import it.unipr.netsec.mjcoap.coap.message.*;
import it.unipr.netsec.mjcoap.coap.provider.*;
import it.unipr.netsec.mjcoap.coap.transaction.*;
import it.unipr.netsec.mjcoap.coap.transmission.CoapReliableReception;

import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.URISyntaxException;


/** A CoAP observe client is a CoAP client that is interested in having a current representation of the resource at any given time.
 * According to the well-known observer design pattern, an observer is a component that register at a specific
 * known provider called the "subject" that they are interested in being notified whenever the subject undergoes a change in state.
 * <p>
 * It implements the observer model according to the RFC 7641 "Observing Resources in CoAP".
 */
public class ObserveTransactionClient {
	
	/** CoAP provider */
	CoapProvider coap_provider;
	
	/** Subject socket address */
	InetSocketAddress server_soaddr;

	/** GET request message */
	CoapRequest req;

	/** Resource URI */
	CoapURI resource_uri;

	/** Token */
	CoapId id=null;
	
	/** Observer listener */
	ObserveTransactionClientListener listener;



	/** Creates a new CoAP observe client.
	 * @param coap_provider the CoAP provider
	 * @param req the GET request for the resource
	 * @param server_soaddr the socket address of the server 
	 * @param listener the listener of the observer (or <i>null</i>) */
	public ObserveTransactionClient(CoapProvider coap_provider, CoapRequest req, InetSocketAddress server_soaddr, ObserveTransactionClientListener listener) {
		log("ObserveTransactionClient()");
		if (!req.isGET()) throw new CoapMessageFormatException("observe request must be a GET message");
		// else
		this.coap_provider=coap_provider;
		this.req=req;
		this.server_soaddr=server_soaddr;
		this.listener=listener;
		try {
			resource_uri=req.getRequestUri();
		}
		catch (URISyntaxException e) {
			throw new CoapMessageFormatException("URISyntaxException: observing registration request must include a valid resource URI");
		}
	}

	
	/** Gets the resource URI.
	 * @return the URI */
	public CoapURI getResourceURI() {
		return resource_uri;
	}


	/** Gets the register request.
	 * @return the register request message */
	public CoapRequest getRequest() {
		return req;
	}


	/** Sends a request to start observing the resource (registration). */
	public void observe() {
		log("observe()");
		req.setObserveRegister();
		id=CoapId.getTransactionId(server_soaddr,req.getToken());
		CoapTransactionClientListener this_tc_listener=new CoapTransactionClientListener() {
			public void onTransactionResponse(CoapTransactionClient tc, CoapResponse resp) {
				processRegistrationResponse(tc,resp);
			}
			public void onTransactionFailure(CoapTransactionClient tc) {
				terminate();
			}
		};
		CoapTransactionClient tc=new CoapTransactionClient(coap_provider,req,server_soaddr,this_tc_listener);
		tc.request();
	}


	/** Sends a request to stop observing the resource (de-registration). */
	public void cancel() throws CoapMessageFormatException {
		if (resource_uri!=null)  {
			CoapTransactionClientListener this_tc_listener=new CoapTransactionClientListener() {
				public void onTransactionResponse(CoapTransactionClient tc, CoapResponse resp) {
					processDeregistrationResponse(tc,resp);
				}
				public void onTransactionFailure(CoapTransactionClient tc) {
					terminate();
				}
			};
			CoapRequest req=CoapMessageFactory.createCONRequest(CoapRequestMethod.GET,resource_uri);
			req.setObserveDeregister();
			CoapTransactionClient tc=new CoapTransactionClient(coap_provider,req,server_soaddr,this_tc_listener);
			tc.request();
		}
	}
	
	
	/** When a CoAP response is received for the observe registration request.
	 * @param tc the transaction client that received the response
	 * @param resp the response */
	private void processRegistrationResponse(CoapTransactionClient tc, CoapResponse resp) {
		log("processRegistrationResponse()");
		CoapResponseCode resp_code=resp.getResponseCode();   
		if (resp_code.isSuccess()) {
			CoapProviderListener this_cp_listener=new CoapProviderListener() {
				public void onReceivedMessage(CoapProvider coap_provider, CoapMessage msg) {
					processReceivedMessage(coap_provider,msg);
				}
			};
			coap_provider.addListener(id,this_cp_listener);
		}
		processReceivedMessage(coap_provider,resp);
	}


	/** When a CoAP response is received for the observe deregistration request.
	 * @param tc the transaction client that received the response
	 * @param resp the response */
	private void processDeregistrationResponse(CoapTransactionClient tc, CoapResponse resp) {
		log("processUnregistrationResponse()");
		processReceivedMessage(coap_provider,resp);
		terminate();
	}

	
	/** When a new CoAP message is received.
	 * @param coap_provider the CoAP provider
	 * @param msg the received CoAP message */
	private void processReceivedMessage(CoapProvider coap_provider, CoapMessage msg) {
		log("processReceivedMessage()");
		if (!msg.isResponse()) return;
		// else
		CoapResponse resp=new CoapResponse(msg);
		if (resp.isCON()) new CoapReliableReception(coap_provider,resp);
		CoapResponseCode resp_code=resp.getResponseCode();
		byte[] state=resp.getPayload();
		int seq_num=resp.getObserveSequenceNumber();
		if (listener!=null) try {  listener.onObserveNotification(this,resp_code,state,seq_num,resp);  } catch (Exception e) {  log("processReceivedMessage(): listener.onNotification(this): "+e.toString());  }
		
		if (!resp_code.isSuccess()) terminate();
	}


	/** Terminates the observation. */
	private void terminate() {
		log("terminate()");
		if (id!=null) {
			coap_provider.removeListener(id);
			id=null;
		}
		if (listener!=null) try {  listener.onObserveClientTerminated(this);  } catch (Exception e) {  log("terminate(): listener.onTermination(this): "+e.getMessage());  }
	}


	/** Logs a message.
	 * @param str the message to be logged */
	private void log(String str) {
		Logger logger=SystemUtils.getDefaultLogger();
		if (logger!=null) logger.log(LoggerLevel.DEBUG,getClass(),str);
	}

}
