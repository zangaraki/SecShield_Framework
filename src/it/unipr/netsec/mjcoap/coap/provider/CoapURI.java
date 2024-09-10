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


import java.net.URI;
import java.net.URISyntaxException;


/** CoAP URI.
 * It includes both "coap" and "coaps" schemes.
 */
public class CoapURI {

	/** Scheme "coap" */
	private static final String COAP="coap";

	/** Scheme "coaps" */
	private static final String COAPS="coaps";

	
	/** URI */
	URI uri;
	
	/** Whether it has "coaps" scheme */
	boolean secure;
	
	
	/** Creates a new CoAP URI.
	 * @param str the URI
	 * @throws URISyntaxException */
	public CoapURI(String str) throws URISyntaxException {
		init(new URI(str));
	}

	/** Creates a new CoAP URI.
	 * @param uri the URI
	 * @throws URISyntaxException */
	public CoapURI(URI uri) throws URISyntaxException {
		init(uri);
	}

	/** Creates a new CoAP URI.
	 * @param host host name
	 * @param path path
	 * @param secure <i>true</i> for "coaps" scheme, <i>false</i> for "coap" scheme 
	 * @throws URISyntaxException */
	public CoapURI(String host, String path, boolean secure) throws URISyntaxException {
		init(new URI(COAP,null,host,-1,path,path,null));
		this.secure=secure;
	}

	/** Creates a new CoAP URI.
	 * @param host host name
	 * @param port port number
	 * @param path path
	 * @param query query
	 * @param secure <i>true</i> for "coaps" scheme, <i>false</i> for "coap" scheme 
	 * @throws URISyntaxException */
	public CoapURI(String host, int port, String path, String query, boolean secure) throws URISyntaxException {
		init(new URI(COAP,null,host,port,path,query,null));
		this.secure=secure;
	}

	private void init(URI uri) throws URISyntaxException {
		this.uri=uri;
		if (uri.getScheme().equalsIgnoreCase(COAP)) secure=false;
		else if (uri.getScheme().equalsIgnoreCase(COAPS)) secure=true;
			else throw new URISyntaxException(uri.toString(),"It doesn't have a CoAP scheme");
		if (uri.getFragment()!=null) throw new URISyntaxException(uri.toString(),"It cannot have a 'fragment' component");
	}
	
	@Override
	public boolean equals(Object obj) {
		if (obj==null) return false;
		if (!(obj instanceof CoapURI)) return false;
		CoapURI coap_uri=(CoapURI)obj;
		return uri.equals(coap_uri.toURI());
	}

	@Override
	public int hashCode() {
		return uri.hashCode();
	}

	/** Whether it has "coaps" scheme.
	 * @return <i>true</i> in case of "coaps"; <i>false</i> in case of "coap" */
	public boolean isSecure() {
		return secure;
	}

	/** Returns host. */
	public String getHost() {
		return uri.getHost();
	}

	/** Returns port. */
	public int getPort() {
		return uri.getPort();
	}

	/** Returns path. */
	public String getPath() {
		return uri.getPath();
	}

	/** Returns query. */
	public String getQuery() {
		return uri.getQuery();
	}

	/** Gets this CoAP URI as a standard {@link java.net.URI java.net.URI}.
	 * @return the URI */
	public URI toURI() {
		return uri;
	}

	@Override
	public String toString() {
		return uri.toString();
	}

}
