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

package it.unipr.netsec.mjcoap.coap.message;


import MyProject.CoapMessage;
import it.unipr.netsec.mjcoap.coap.provider.CoapURI;


/** Collects some static methods for simplifying the creation of CoAP messages.
 */
public class CoapMessageFactory {
	

	// CoAP MESSAGES:

	/** Creates an ACK.
	 * @param msg the message to be confirmed with the ACK
	 * @return the ACK message */
	/*public static CoapMessage createAck(CoapMessage msg) {
		return new CoapMessage(CoapMessageTypeACK,CoapMessage.EMPTY,msg.getMessageId());
	}*/
		  

	// CoAP REQUESTS:

	/** Creates a new request.
	  * @param confirmable whether the request should be CON (true) or NON (false)
	  * @param method the request method (GET, POST, PUT, or DELETE)
	  * @param options the options, if any
	  * @param payload the payload, if present
	  * @return the (CON or NON) request */
	/*public static CoapRequest createRequest(boolean confirmable, CoapRequestMethod method, CoapOption[] options, byte[] payload) {
		try {
			CoapMessageType type=(confirmable)? CoapMessageType.CON : CoapMessageType.NON;
			CoapRequest req=new CoapRequest(type,method,CoapMessage.pickMessageId());
			if (TOKEN_LEN>0) req.setToken(CoapMessage.pickToken(TOKEN_LEN));
			req.setOptions(options);
			req.setPayload(payload);
			return req;
		}
		catch (CoapMessageFormatException e) {
			e.printStackTrace();
			return null;
		}
	}*/  


	/** Creates a new request.
	  * @param confirmable whether the request should be CON (true) or NON (false)
	  * @param method the request method (GET, POST, PUT, or DELETE)
	  * @param request_uri the resource URI
	  * @return the (CON or NON) request */
	public static CoapRequest createRequest(boolean confirmable, CoapRequestMethod method, CoapURI request_uri) {
		try {
			CoapMessageType type=(confirmable)? CoapMessageType.CON : CoapMessageType.NON;
			CoapRequest req=new CoapRequest(type,method,CoapMessage.pickMessageId());
			if (CoapMessage.DEFAULT_TOKEN_LEN>0) req.setToken(CoapMessage.pickToken(CoapMessage.DEFAULT_TOKEN_LEN));
			if (request_uri!=null) req.setRequestURI(request_uri);
			return req;
		}
		catch (CoapMessageFormatException e) {
			e.printStackTrace();
			return null;
		}
	}   


	/** Creates a new CoAP CONfirmable request.
	  * @param method the request method (GET, POST, PUT, or DELETE)
	  * @param request_uri the resource URI
	  * @return the new request message */
	public static CoapRequest createCONRequest(CoapRequestMethod method, CoapURI request_uri) {
		//CoapRequest req=createRequest(true,method,null,null);
		//if (request_uri!=null) req.setRequestURI(request_uri);
		//return req;
		return createRequest(true,method,request_uri);
	}

  
	/** Creates a new CoAP NON-confirmable request.
	  * @param method the request method (GET, POST, PUT, or DELETE)
	  * @param request_uri the resource URI
	  * @return the new request message */
	public static CoapRequest createNONRequest(CoapRequestMethod method, CoapURI request_uri) {
		//CoapRequest req=createRequest(false,method,null,null);
		//if (request_uri!=null) req.setRequestURI(request_uri);
		//return req;
		return createRequest(false,method,request_uri);
	}

 
	/** Creates a new CoAP GET request.
	  * @param */
	/*public static BasicCoapMessage createGET(boolean confirmable, URI request_uri) {
		CoapOption[] options=getUriOptions(request_uri);
		CoapRequest req=createRequest(confirmable,CoapRequestMethod.GET.getCode(),options,null);
		return req;
	}*/

	
	/** Creates a new CoAP PUT request.
	 * @param */
	/*public static BasicCoapMessage createPUT(boolean confirmable, URI request_uri, byte[] payload) {
		CoapOption[] options=getUriOptions(request_uri);
		CoapRequest req=createRequest(confirmable,CoapRequestMethod.PUT.getCode(),options,payload);
		return req;
	}*/

  
	/** Creates a new CoAP POST request.
	 * @param */
	/*public static BasicCoapMessage createPOST(boolean confirmable, URI request_uri, byte[] payload) {
		CoapOption[] options=getUriOptions(request_uri);
		CoapRequest req=createRequest(confirmable,CoapRequestMethod.POST.getCode(),options,payload);
		return req;
	}*/

 
	/** Creates a new CoAP DELETE request.
	  * @param */
	/*public static BasicCoapMessage createDELETE(boolean confirmable, URI request_uri) {
		CoapOption[] options=getUriOptions(request_uri);
		CoapRequest req=createRequest(confirmable,CoapRequestMethod.DELETE.getCode(),options,null);
		return req;
	}*/

	
	// RESPONSES:
	
	/** Creates a new response based on a request.
	 * @param req the originated request
	 * @param response_code the response code
	 * @return CON response for CON request or NON response for NON request */
	public static CoapResponse createResponse(CoapRequest req, CoapResponseCode response_code) {
		try {
			CoapResponse resp=new CoapResponse(req.getType(),response_code,CoapMessage.pickMessageId());
			resp.setToken(req.getToken());
			return resp;
		}
		catch (CoapMessageFormatException e) {
			e.printStackTrace();
			return null;
		}
	}


	/** Creates a new piggybacked response based on a request.
	 * @param req the originated request
	 * @param response_code the response code
	 * @return piggy-backed ACK response for CON request or NON response for NON request */
	public static CoapResponse createPiggyBackedResponse(CoapRequest req, CoapResponseCode response_code) {
		if (!req.isCON()) return createResponse(req,response_code);
		// else
		try {
			CoapResponse resp=new CoapResponse(CoapMessageType.ACK,response_code,req.getMessageId());
			resp.setToken(req.getToken());
			return resp;
		}
		catch (CoapMessageFormatException e) {
			e.printStackTrace();
			return null;
		}
	}

}
