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

package it.unipr.netsec.mjcoap.coap.transmission;


import java.net.InetSocketAddress;

import org.zoolu.util.*;

import MyProject.CoapMessage;
import it.unipr.netsec.mjcoap.coap.provider.CoapId;
import it.unipr.netsec.mjcoap.coap.provider.CoapProvider;
import it.unipr.netsec.mjcoap.coap.provider.CoapProviderListener;


/** CoAP reliable transmission.
  * It can be used to send CONfirmable CoAP messages. 
  */
public class CoapReliableTransmission {
	
	/** ACK_TIMEOUT [millisec] */
	public static long ACK_TIMEOUT=2000;
	
	/** ACK_RANDOM_FACTOR */
	public static double ACK_RANDOM_FACTOR=1.5;
  
	/** MAX_RETRANSMIT */
	public static int MAX_RETRANSMIT=4;
  
	/** NSTART */
	public static int NSTART=1;
  
	/** DEFAULT_LEISURE [millisec] */
	public static long DEFAULT_LEISURE=5000;
  
	/** PROBING_RATE [Byte/sec] */
	public static int PROBING_RATE=1;
	
	

	/** CoapReliableTransmission listener */
	CoapReliableTransmissionListener reliable_transmission_listener;

	/** CoapProvider */
	CoapProvider coap_provider;

	/** CoAP message */
	CoapMessage msg;

	/** Remote socket address */
	InetSocketAddress remote_soaddr;

	/** Retransmission counter */
	int retransmission_counter;

	/** Retransmission timer */
	long retransmission_timout;

	/** Retransmission timer */
	Timer timer;

	/** Retransmission timer */
	TimerListener timer_listener;



	/** Creates a new CoapReliableTransmission. */
	public CoapReliableTransmission(CoapProvider coap_provider, InetSocketAddress remote_soaddr, CoapReliableTransmissionListener reliable_transmission_listener) {
		this.coap_provider=coap_provider;
		this.reliable_transmission_listener=reliable_transmission_listener;
		this.remote_soaddr=remote_soaddr;
	}


	/** Sends CoAP message. */
	public void send(CoapMessage msg) {
		if (!msg.isCON()) throw new RuntimeException("NON-confirmable message cannot be transmitted reliablely");
		// else
		this.msg=msg;
		CoapProviderListener this_cp_listener=new CoapProviderListener() {
			public void onReceivedMessage(CoapProvider coap_provider, CoapMessage msg) {
				processReceivedMessage(coap_provider,msg);
			}
		};
		coap_provider.addListener(CoapId.getReliableTransmissionId(remote_soaddr,msg.getMessageId()),this_cp_listener);
		coap_provider.send(msg,remote_soaddr);
		// start retransmission procedure
		timer_listener=new TimerListener() {
			public void onTimeout(Timer t) {
				processTimeout(t);
			}
		};
		retransmission_counter=0;
		retransmission_timout=ACK_TIMEOUT+Random.nextInt((int)(ACK_TIMEOUT*(ACK_RANDOM_FACTOR-1)));
		timer=new Timer(retransmission_timout,timer_listener);
		timer.start();
	}


	/** Stops retransmission. */
	public void terminate() {
		log("terminate()");
		if (timer!=null) timer.halt();
		timer=null;
	}


	/** When a new CoAP message is received. */
	private void processReceivedMessage(CoapProvider coap_provider, CoapMessage msg) {
		log("processReceivedMessage("+msg.toString()+")");
		coap_provider.removeListener(CoapId.getReliableTransmissionId(remote_soaddr,msg.getMessageId()));
		terminate();
		if (msg.isACK()) {
			if (reliable_transmission_listener!=null) reliable_transmission_listener.onTransmissionAcknowledgement(this,msg);
		}
		else
		if (msg.isRST()) {
			if (reliable_transmission_listener!=null) reliable_transmission_listener.onTransmissionReject(this,msg);
		}
	}
	
	
	/** When the Timer exceeds. */
	private void processTimeout(Timer t) {
		if (t==timer) {
			log("processTimeout()");
			if (retransmission_counter<MAX_RETRANSMIT) {
				coap_provider.send(msg,remote_soaddr);
				retransmission_counter++;
				retransmission_timout*=2;
				timer=new Timer(retransmission_timout,timer_listener);
				timer.start();
			}
			else {
				timer=null;
				if (reliable_transmission_listener!=null) reliable_transmission_listener.onTransmissionTimeout(this);
			}
		}
	}


	/** Logs a message. */
	private void log(String message) {
		Logger logger=SystemUtils.getDefaultLogger();
		if (logger!=null) logger.log(LoggerLevel.TRACE,getClass(),message);
	}

}
