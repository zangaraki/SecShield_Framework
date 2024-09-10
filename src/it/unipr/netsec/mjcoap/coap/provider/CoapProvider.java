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

package it.unipr.netsec.mjcoap.coap.provider;


import MyProject.CoapMessage;
import org.zoolu.net.*;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.mjcoap.coap.analyzer.CoapProtocolAnalyzer;
import it.unipr.netsec.mjcoap.coap.message.*;

import java.util.Hashtable;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Enumeration;


/** CoAP message communication service (i.e. the CoAP messaging layer) for sending and receiving CoAP messages.
 * <p>
 * For sending a CoAP message you have just to pass the given {@link CoapMessage message}
 * and the target {@link InetSocketAddress socket address} to the method {@link #send(CoapMessage, InetSocketAddress)}.
 * <p>
 * For receiving CoAP messages you have to create a {@link CoapProviderListener}
 * (implementing the {@link CoapProviderListener#onReceivedMessage(CoapProvider, CoapMessage)} method)
 * and call the method {@link #addListener(CoapId, CoapProviderListener)} specifying also the kind of messages you are interested to receive.
 * This is achieved by passing a {@link CoapId} that identifies the message context for which you want to receive messages.
 * The message context should be one of the following:
 * <ol>
 * <li>reliable transmission</li>
 * <li>transaction (i.e. request/response exchange)</li>
 * <li>blockwise transfer</li>
 * <li>message method (GET, PUT, POST, DELETE)</li>
 * <li>message type (request or response)</li>
 * <li>any</li>
 * </ol>
 * Class {@link CoapId} provides methods for creating identifiers of any of the above types.
 * When the CoAP layer receives a message, it passes the message to the listener of the first message context according to the order of above list.
 * That is, if a listener for a reliable transmission that matches the message is found, that listener is called, otherwise a listener
 * for the request/response transaction, a blockwise transfer, message method, or message type is searched. If no listener for any previous context
 * is found, the listener for all message (if present) is used.
 */
public class CoapProvider {
	
	/** Value for automatic assignment of the CoAP UDP port */
	public static final int DYNAMIC_PORT=0;
	
	/** Default CoAP UDP port 5683 */
	public static final int DEFAUL_PORT=5683;


	/** Method listeners (Hashtable<CoapId,CoapProviderListener>) */
	Hashtable<CoapId,CoapProviderListener> listeners=new Hashtable<CoapId,CoapProviderListener>();

	/** UDP provider */
	UdpProvider udp_provider;



	/** Creates a new CoAP provider.
	 * No transport protocol service is created. */
	protected CoapProvider() {
	}

  
	/** Creates a new CoAP provider.
	  * @param port the local UDP port number */
	public CoapProvider(int port) throws java.net.SocketException {
		init(new DatagramSocket(port));
	}

	
	/** Creates a new CoAP provider.
	 * @param udp_socket the UDP socket */
	public CoapProvider(DatagramSocket udp_socket) {
		init(udp_socket);
	}

  
	/** Initializes the CoAP provider.
	 * @param udp_socket the UDP socket */
	private void init(DatagramSocket udp_socket) {
		UdpProviderListener udp_provider_listener=new UdpProviderListener() {
			public void onReceivedPacket(UdpProvider udp, DatagramPacket packet) {
				processReceivedPacket(udp,packet);
			}
			public void onServiceTerminated(UdpProvider udp, Exception error) {
				processServiceTerminated(udp,error);
			}
		};
		udp_provider=new UdpProvider(udp_socket,udp_provider_listener);
	}

  
	/** Gets CoAP port.
	 * @return the local UDP port used by CoAP */
  public int getPort()
  {  try {  return udp_provider.getSocket().getLocalPort();  } catch (Exception e) {  return -1;  } 
  }


	/** Adds a new CoapProvider listener.
	  * @param id the identifier of a CoAP method, of a reliable transmission, or of a transaction; it specifies the kind of messages that the listener is interested to receive. <br>
	  *  Use the proper <i>get</i> method of class {@link CoapId} (e.g. <i>CoapId.getMethodId(CoapRequestMethod.GET)</i>,
	  *  or <i>CoapId.getTransactionId(msg.getRemoteSocketAddress(),msg.getToken())</i>,
	  *  or <i>CoapId.getReliableTransmissionId(msg.getRemoteSocketAddress(),msg.getMessageId())</i>), for capturing only the messages you are interested in. <br>
	  *  Otherwise, you can use {@link CoapId#REQUEST} for capturing all request messages, or {@link CoapId#ANY} for capturing all messages (both requests and responses)
	  * @param listener the CoapProvider listener */
	public void addListener(CoapId id, CoapProviderListener listener) {
		trace("addListener(): "+listener+", "+id);
		if (listeners.containsKey(id)) warning("addListener(): found a previous listener for "+id+": replaced");
		listeners.put(id,listener);
	}


	/** Removes a CoapProvider listener.
	  * @param id the identifier of a CoAP method, a reliable transmission, or a transaction, associated to the listener that has to be removed */
	public void removeListener(CoapId id) {
		trace("removeListener(id): "+id);
		if (!listeners.containsKey(id)) warning("removeListener(id): listener for "+id+" not found");
		else listeners.remove(id);
	}


	/** Removes a CoapProvider listener.
	  * @param listener the listener that has to be removed */
	public void removeListener(CoapProviderListener listener) {
		for (Enumeration<CoapId> i=listeners.keys(); i.hasMoreElements(); ) {
			Object key=i.nextElement();
			if (listeners.get(key)==listener) {
				trace("removeListener(listener): id: "+listener+", "+key);
				listeners.remove(key);
				return;
			}
		}
		// else
		warning("removeListener(listener): listener "+listener+" not found");
	}


	/** Sends a new CoAP message.
	  * @param msg the CoAP message */
	/*public void send(CoapMessage msg) {
		printLog("send("+msg.toString()+")");
		InetSocketAddress remote_soaddr=msg.getRemoteSoAddress();
		if (remote_soaddr!=null) send(msg,remote_soaddr);
		else {
			// try to use request URI
			// TODO..
			printLog("send(): no destination address found");
		}
	}*/


	/** Sends a new CoAP message.
	  * @param msg the CoAP message
	  * @param remote_soaddr the remote socket address where the message has to be sent to */
	public void send(CoapMessage msg, InetSocketAddress remote_soaddr) {
		debug("send(): "+msg.toString()+","+InetAddrUtils.toString(remote_soaddr));
		trace("send(): "+CoapProtocolAnalyzer.analyze(msg).toString(2));
		try {
			byte[] data=msg.getBytes();
			InetAddress remote_ipaddr=remote_soaddr.getAddress();
			int remote_port=remote_soaddr.getPort();
			if (remote_port<=0) remote_port=DEFAUL_PORT;
			udp_provider.send(new DatagramPacket(data,data.length,remote_ipaddr,remote_port));
		}
		catch (java.io.IOException e) {
			e.printStackTrace();
		}
	}


	/** Stops the CoAP provider. */
	public void halt() {
		listeners.clear();
		final DatagramSocket udp_socket=udp_provider.getSocket();
		udp_provider.halt();
		new Thread() {
			public void run() {
				try {  Thread.sleep(2000);  } catch (Exception e) {}
				udp_socket.close();
			}
		}.start();
		//udp_provider=null;
	}


	/** When a new UDP datagram is received.
	  * @param udp the UDP provider
	  * @param packet the received UDP datagram */
	private void processReceivedPacket(UdpProvider udp, DatagramPacket packet) {
		trace("processReceivedPacket()");
		try {
			CoapMessage msg=new CoapMessage(packet.getData(),packet.getOffset(),packet.getLength());
			msg.setRemoteSoAddress(new InetSocketAddress(packet.getAddress(),packet.getPort()));
			processReceivedMessage(msg);
		}
		catch (CoapMessageFormatException e) {
			e.printStackTrace();
		}
		catch (RuntimeException e) {
			e.printStackTrace();
		}
	}


	/** When a new CoAP message is received.
	  * @param msg the CoAP message */
	protected void processReceivedMessage(CoapMessage msg) {
		debug("processReceivedMessage(): "+msg.toString());
		trace("processReceivedMessage(): "+CoapProtocolAnalyzer.analyze(msg).toString(2));
		InetSocketAddress remote_soddr=msg.getRemoteSoAddress();
		CoapId id=CoapId.getReliableTransmissionId(remote_soddr,msg.getMessageId());
		trace("processReceivedMessage(): transmission-id: "+id);
		if (listeners.containsKey(id)) ((CoapProviderListener)listeners.get(id)).onReceivedMessage(this,msg);
		else {
			byte[] token=msg.getToken();
			id=(token!=null)? CoapId.getTransactionId(remote_soddr,token) : null;
			trace("processReceivedMessage(): transaction-id: "+id);
			if (id!=null && listeners.containsKey(id)) ((CoapProviderListener)listeners.get(id)).onReceivedMessage(this,msg);
			else {
				CoapRequestMethod method=(msg.isRequest())? CoapRequestMethod.getMethodByCode(msg.getCode()) : null;
				id=(method!=null)? CoapId.getTransferId(remote_soddr,method,new CoapRequest(msg).getRequestUriPath()) : null;
				trace("processReceivedMessage(): transfer-id: "+id);
				if (id!=null && listeners.containsKey(id)) ((CoapProviderListener)listeners.get(id)).onReceivedMessage(this,msg);
				else {
					id=(method!=null)? CoapId.getMethodId(method) : null;
					trace("processReceivedMessage(): method-id: "+id);
					if (id!=null && listeners.containsKey(id)) ((CoapProviderListener)listeners.get(id)).onReceivedMessage(this,msg);
					else {
						//if (msg.isRequest() && listeners.containsKey(CoapId.REQUEST)) ((CoapProviderListener)listeners.get(CoapId.REQUEST)).onReceivedMessage(this,msg);
						if (method!=null && listeners.containsKey(CoapId.REQUEST)) ((CoapProviderListener)listeners.get(CoapId.REQUEST)).onReceivedMessage(this,msg);
						else {
							if (listeners.containsKey(CoapId.ANY)) ((CoapProviderListener)listeners.get(CoapId.ANY)).onReceivedMessage(this,msg);
							else {
								debug("processReceivedMessage(): no listener found");
								if (msg.isCON()) send(new CoapMessage(CoapMessageType.RST,CoapMessage.EMPTY,msg.getMessageId()),msg.getRemoteSoAddress());
							}
						}
					}
				}
			}
		}		
	}

		
	/** When UdpProvider terminates.
	  * @param udp the UDP provider
	  * @param error the error that caused the termination, or <i>null</i> */
	private void processServiceTerminated(UdpProvider udp, Exception error)  {
		//if (listener!=null) listener.onServiceTerminated(this,error);
		// do something
		String reason=error==null? "halted" : error.getMessage();
		debug("UDP provider terminated: "+reason);		
	}  


	/** Logs a warning message.
	  * @param str the message to be logged */
	private void warning(String str) {
		SystemUtils.log(LoggerLevel.WARNING,null,toString()+": "+str);
	}

	
	/** Logs a debug message.
	  * @param str the message to be logged */
	private void debug(String str) {
		SystemUtils.log(LoggerLevel.DEBUG,null,toString()+": "+str);
	}

	
	/** Logs a verbose (trace) message.
	  * @param str the message to be logged */
	private void trace(String str) {
		SystemUtils.log(LoggerLevel.TRACE,null,toString()+": "+str);
	}


	/** Gets the CoAP URI of this end-point.
	 * @return the URI */
	/*public String getURI() {
		DatagramSocket udp_socket=udp_provider.getSocket();
		return "coap://"+udp_socket.getLocalAddress().getHostAddress()+":"+udp_socket.getLocalPort();
	}*/

	
	@Override
	public String toString() {
		DatagramSocket udp_socket=udp_provider.getSocket();
		if (udp_socket.isClosed()) return getClass().getSimpleName()+"[closed]";
		return getClass().getSimpleName()+'['+udp_socket.getLocalAddress().getHostAddress()+":"+udp_socket.getLocalPort()+']';
	}

}
