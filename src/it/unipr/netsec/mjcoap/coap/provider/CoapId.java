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

package it.unipr.netsec.mjcoap.coap.provider;


import java.net.InetSocketAddress;

import org.zoolu.util.ByteUtils;
import org.zoolu.util.Identifier;

import it.unipr.netsec.mjcoap.coap.message.CoapRequestMethod;


/** CoapId identifies a given CoAP message context.
 * The message context can be any of the following:
 * <ul>
 * <li>reliable transmission</li>
 * <li>transaction (i.e. request/response exchange)</li>
 * <li>blockwise transfer</li>
 * <li>message method (GET, PUT, POST, DELETE)</li>
 * <li>message type ({@link #REQUEST} or response)</li>
 * <li>{@link #ANY}</li>
 * </ul>
 */
public class CoapId extends Identifier {
	
	/** CoapId for capturing any request message. */
	public static final CoapId REQUEST=new CoapId("REQUEST"){};

	/** CoapId for capturing any response message. */
	//public static final CoapId RESPONSE=new CoapId("RESPONSE"){};	
	
	/** CoapId for capturing any message. */
	public static final CoapId ANY=new CoapId("ANY"){};


	/** Creates a void CoapId. */
	protected CoapId() {
		super();
	}

	/** Creates a new CoapId.
	 * @param str_id the string value of the identifier */
	protected CoapId(String str_id) {
		super(str_id);
	}

	/** Creates a new CoapId.
	 * @param id a CoAP identifier */
	protected CoapId(CoapId id) {
		super(id);
	}

	/** Gets a reliable transmission identifier.
	 * @param remote_soaddr the socket address of the remote end-point
	 * @param message_id the message-id
	 * @return the string value for a reliable transmission identifier */
	public static CoapId getReliableTransmissionId(InetSocketAddress remote_soaddr, int message_id) {
		return new CoapId("transmission-messageid-"+endpoint(remote_soaddr)+'-'+message_id);
	}

	
	/** Gets a transaction identifier.
	 * @param remote_soaddr the socket address of the remote end-point
	 * @param token the message token
	 * @return the string value for a transaction identifier */
	public static CoapId getTransactionId(InetSocketAddress remote_soaddr, byte[] token) {
		return new CoapId("transaction-token-"+endpoint(remote_soaddr)+'-'+ByteUtils.asHex(token));
	}

	
	/** Gets a transfer identifier.
	 * @param remote_soaddr the socket address of the remote end-point
	 * @param method the CoAP method
	 * @param request_uri the request URI
	 * @return the transfer identifier */
	public static CoapId getTransferId(InetSocketAddress remote_soaddr, CoapRequestMethod method, String request_uri) {
		return new CoapId("blockwise-transfer-"+endpoint(remote_soaddr)+'-'+method.getName()+request_uri);
	}

	
	/** Gets the string value of the method identifier.
	 * @param method the CoAP method
     * @return the method identifier */
	public static CoapId getMethodId(CoapRequestMethod method) {
		return new CoapId("method-"+method.getName());
	}

	
	/** Gets a string representation of an end-point.
	 * @param remote_soaddr the socket address of the remote end-point
	 * @return the concatenation of IP address, a colon ':', and port number */
	private static String endpoint(InetSocketAddress remote_soaddr) {
		String host=remote_soaddr.getAddress().getHostAddress();
		int port=remote_soaddr.getPort();
		if (port<=0) port=CoapProvider.DEFAUL_PORT;
		return host+':'+port;
	}

}
