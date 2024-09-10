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
import java.net.MalformedURLException;
import java.net.URISyntaxException;

import it.unipr.netsec.mjcoap.coap.option.*;
import it.unipr.netsec.mjcoap.coap.provider.CoapURI;


/** CoAP request message, with method for handling CoAP-specific options.
 */
public class CoapRequest extends CoapMessage {
	

	/** Creates a new CoapRequest.
	 * @param msg a CoAP message to be copied */
	public CoapRequest(CoapMessage msg) {
		super(msg);
	}


	/** Creates a new CoapRequest.
	 * @param type message type (Confirmable (0), Non-Confirmable (1), Acknowledgement (2) or Reset (3))
	 * @param method the request method (GET, POST, PUT, or DELETE)
	 * @param message_id message ID, used for the detection of message duplication, and to match messages of type Acknowledgement/Reset to messages of type Confirmable/Non-confirmable */
	public CoapRequest(CoapMessageType type, CoapRequestMethod method, int message_id) {
		super(type,method.getCode(),message_id);
	}


	/** Creates a new CoapRequest.
	 * @param type message type (Confirmable (0), Non-Confirmable (1), Acknowledgement (2) or Reset (3))
	 * @param method the request method (GET, POST, PUT, or DELETE)
	 * @param message_id message ID, used for the detection of message duplication, and to match messages of type Acknowledgement/Reset to messages of type Confirmable/Non-confirmable
	 * @param token the token used to correlate requests and responses (if any)
	 * @param options array of message options (if any)
	 * @param payload message payload */
	/*public CoapRequest(CoapMessageType type, CoapRequestMethod method, int message_id, byte[] token, CoapOption[] options, byte[] payload) {
		super(type,method.getCode(),message_id,token,options,payload);
	}*/


	/** Creates a new CoapRequest.
	 * @param type message type (Confirmable (0), Non-Confirmable (1), Acknowledgement (2) or Reset (3))
	 * @param method the request method (GET, POST, PUT, or DELETE)
	 * @param message_id message ID, used for the detection of message duplication, and to match messages of type Acknowledgement/Reset to messages of type Confirmable/Non-confirmable
	 * @param token the token used to correlate requests and responses (if any)
	 * @param options list of message options (if any)
	 * @param payload message payload */
	/*public CoapRequest(CoapMessageType type, CoapRequestMethod method, int message_id, byte[] token, List<CoapOption> options, byte[] payload) {
		super(type,method.getCode(),message_id,token,options,payload);
	}*/


	/** Whether it is a GET request.
	 * @return <i>true</i> in case of a GET request */
	public boolean isGET() {
		return getCode()==CoapRequestMethod.GET.getCode();
	}

	/** Whether it is a POST request.
	 * @return <i>true</i> in case of a POST request */
	public boolean isPOST() {
		return getCode()==CoapRequestMethod.POST.getCode();
	}

	/** Whether it is a PUT request.
	 * @return <i>true</i> in case of a PUT request */
	public boolean isPUT() {
		return getCode()==CoapRequestMethod.PUT.getCode();
	}
 

	/** Whether it is a DELETE request.
	* @return <i>true</i> in case of a DELETE request */
	public boolean isDELETE() {
		return getCode()==CoapRequestMethod.DELETE.getCode();
	}
	
	
	/** Gets message code as string.
	 * @return "empty" for empty message, "GET" for GET request, "POST" for POST request, "PUT" for PUT request, "DELETE" for DELETE request, or response code descrition for responses */
	@Override
	public String getCodeAsString() {
		//return CoapRequestMethod.getMethodByCode(getCode()).toString();
		return getMethod().toString();
	}

	
	/** Gets request method.
	 * @return the CoAP request method */
	public CoapRequestMethod getMethod() {
		return CoapRequestMethod.getMethodByCode(getCode());
	}

	
	// METHODS FOR GETTING AND SETTING OPTIONS THAT APPLY ONLY TO REQUESTS
 
	/** Sets the target resource URI options (Uri-Host, Uri-Port, Uri-Path, and Uri-Query options).
	  * @param uri the URI of the target resource
	  * @return this message
	  * @throws CoapMessageFormatException */
	public CoapRequest setRequestURI(CoapURI uri) throws CoapMessageFormatException {
		String host=uri.getHost();
		int port=uri.getPort();
		String path=uri.getPath();
		String query=uri.getQuery();
		return setRequestURI(host,port,path,query);
	}

	/** Sets the target resource URI options (Uri-Host, Uri-Port, Uri-Path, and Uri-Query options).
	  * @param host the URI host, that is the Internet host of the resource being requested
	  * @param port the URI port, that is the transport-layer port number of the resource
	  * @param path the URI path, that is the absolute path to the resource
	  * @param query the URI query, that is the query of resource parameters
	  * @return this message */
	public CoapRequest setRequestURI(String host, int port, String path, String query) {
		if (host!=null && host.length()>0) addOption(new CoapOption(CoapOptionNumber.UriHost,host));
		if (port>0) addOption(new UriPortOption(port));
		if (path!=null && path.length()>0 && !path.equals("/")) {
			String[] path_components=path.substring(1).split("/");
			for (int i=0; path_components!=null && i<path_components.length; i++) {
				addOption(new UriPathOption(path_components[i]));
			}
		}
		if (query!=null) {
			String[] query_components=query.split("&");
			for (int i=0; query_components!=null && i<query_components.length; i++) {
				addOption(new UriQueryOption(query_components[i]));
			}
		}
		return this;
	}

	/** Gets the target resource URI (from Uri-Host, Uri-Port, Uri-Path, and Uri-Query options).
	  * @return the URI 
	 * @throws URISyntaxException */
	public CoapURI getRequestUri() throws URISyntaxException {
		// host
		CoapOption host_opt=getOption(CoapOptionNumber.UriHost);
		String host=host_opt!=null? host_opt.getValueAsString() : null;
		// port
		CoapOption port_opt=getOption(CoapOptionNumber.UriPort);
		int port=port_opt!=null? (int)port_opt.getValueAsUnit() : -1;
		// path
		CoapOption[] path_opt=getOptions(CoapOptionNumber.UriPath);
		String path=null;
		if (path_opt!=null) {
			StringBuffer sb=new StringBuffer();
			for (int i=0; i<path_opt.length; i++) sb.append('/').append(path_opt[i].getValueAsString());
			path=sb.toString();
		}
		// query
		CoapOption[] query_opt=getOptions(CoapOptionNumber.UriQuery);
		String query=null;
		if (query_opt!=null && query_opt.length>0) {
			StringBuffer sb=new StringBuffer().append('?').append(query_opt[0].getValueAsString());
			for (int i=1; i<query_opt.length; i++) sb.append('&').append(query_opt[i].getValueAsString());
			query=sb.toString();
		}
		return new CoapURI(host,port,path,query,false);
	}

	/** Gets the target resource path (from Uri-Path option).
	 * @return the path */
	public String getRequestUriPath() {
		CoapOption[] path_opt=getOptions(CoapOptionNumber.UriPath);
		if (path_opt!=null) {
			StringBuffer sb=new StringBuffer();
			for (int i=0; i<path_opt.length; i++) sb.append('/').append(path_opt[i].getValueAsString());
			return sb.toString();
		}
		else return null;
	}

	
	/** Sets the proxy absolute-URI (Proxy-Uri option).
	 * @param uri the URI
	 * @return this message */
	public CoapRequest setProxyURI(String uri) {
		if (uri!=null) setOption(new ProxyUriOption(uri));
		return this;
	}

	/** Gets the proxy absolute-URI (from Proxy-Uri option).
	 * @return the URI */
	public String getProxyURI() {
		CoapOption opt=getOption(CoapOptionNumber.ProxyUri);
		if (opt!=null) return opt.getValueAsString();
		else return null;
	}


	/** Sets the proxy scheme (Proxy-Scheme option).
	 * @param scheme the scheme
	 * @return this message */
	public CoapRequest setProxyScheme(String scheme) {
		if (scheme!=null) setOption(new ProxySchemeOption(scheme));
		return this;
	}

	/** Gets the proxy scheme (from Proxy-Scheme option).
	 * @return the scheme */
	public String getProxyScheme() {
		CoapOption opt=getOption(CoapOptionNumber.ProxyScheme);
		if (opt!=null) return opt.getValueAsString();
		else return null;
	}

	
	/** Sets the accepted format (Accept option).
	 * @param format the accepted format
	 * @return this message */
	public CoapRequest setAcceptedFormat(int format) {
		if (format>=0) setOption(new AcceptOption(format));
		return this;
	}

	/** Gets the accepted format (from Accept option).
	 * @return the accepted format */
	public int getAcceptedFormat() {
		CoapOption opt=getOption(CoapOptionNumber.Accept);
		if (opt!=null) return (int)opt.getValueAsUnit();
		else return -1;
	}

	
	/** Adds an entity-tag (ETag option).
	 * @param entity_tag the entity-tag
	 * @return this message */
	public CoapMessage addEntityTag(byte[] entity_tag) {
		if (entity_tag!=null) addOption(new ETagOption(entity_tag));
		return this;
	}

	/** Gets the entity-tags (from ETag options).
	 * @return an array of entity-tag */
	public byte[][] getEntityTags() {
		CoapOption[] etag_opts=getOptions(CoapOptionNumber.ETag);
		if (etag_opts!=null) {
			byte[][] etags=new byte[etag_opts.length][];
			for (int i=0; i<etags.length; i++) etags[i]=etag_opts[i].getValueAsOpaque();
			return etags;
		}
		else return null;
	}


	/** Sets observe registration option.
	 * @return this message */
	public CoapRequest setObserveRegister() {
		setOption(new ObserveOption(ObserveOption.REGISTER));
		return this;
	}

	/** Whether it has the observe registration option.
	 * @return <i>true</i> if it has the registration option */
	public boolean hasObserveRegister() {
		if (hasOption(CoapOptionNumber.Observe) && new ObserveOption(getOption(CoapOptionNumber.Observe)).isRegister()) return true;
		else return false;
	}

	/** Sets observe deregistration option.
	 * @return this message */
	public CoapRequest setObserveDeregister() {
		setOption(new ObserveOption(ObserveOption.UNREGISTER));
		return this;
	}

	/** Whether it has the observe deregistration option.
	 * @return <i>true</i> if it has the deregistration option */
	public boolean hasObserveDeregister() {
		if (hasOption(CoapOptionNumber.Observe) && new ObserveOption(getOption(CoapOptionNumber.Observe)).isUnregister()) return true;
		else return false;
	}

}

