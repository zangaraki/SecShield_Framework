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


import org.zoolu.util.ByteUtils;

import it.unipr.netsec.mjcoap.coap.message.CoapRequest;
import it.unipr.netsec.mjcoap.coap.option.ContentFormatOption;

import java.util.HashSet;
import java.util.Iterator;


/** Server resource.
 */
public class CoapResource {

	/** Format text/plain;charset=utf-8 */
	public static final int FORMAT_TEXT_PLAIN_UTF8=ContentFormatOption.FORMAT_TEXT_PLAIN_UTF8;
	
	/** Format application/link-format */
	public static final int FORMAT_APP_LINK_FORMAT=ContentFormatOption.FORMAT_APP_LINK_FORMAT;
	
	/** Format application/xml */
	public static final int FORMAT_APP_XML=ContentFormatOption.FORMAT_APP_XML;

	/** Format application/octet-stream */
	public static final int FORMAT_APP_OCTECT_STREAM=ContentFormatOption.FORMAT_APP_OCTECT_STREAM;

	/** Format application/exi */
	public static final int FORMAT_APP_EXI=ContentFormatOption.FORMAT_APP_EXI;

	/** Format application/json */
	public static final int FORMAT_APP_JSON=ContentFormatOption.FORMAT_APP_JSON;

	
	/** Gets a string representation of a content-format.
	 * @param content_format content format identifier
	 * @return the string representation of the content-format */
	public static String getContentFormat(int content_format) {
		return ContentFormatOption.getContentFormat(content_format);
	}
	
	
	/** Gets a content-format identifier.
	 * @param content_format the string representation of the content-format
	 * @return the content format identifier */
	public static int getContentFormatIdentifier(String content_format) {
		return ContentFormatOption.getContentFormatIdentifier(content_format);
		
	}
	
	
	/** Resource name */		
	String name;

	/** Resource value format */		
	int format;

	/** Resource value */		
	byte[] value;
	
	/** Active observe requests */
	HashSet<CoapRequest> observe_requests=new HashSet<CoapRequest>();


	/** Creates a new resource.
	 * @param name resource name
	 * @param value resource value */
	public CoapResource(String name, byte[] value) {
		init(name,-1,value);
	}
	
	/** Creates a new resource.
	 * @param name resource name
	 * @param format resource value format
	 * @param value resource value */
	public CoapResource(String name, int format, byte[] value) {
		init(name,format,value);
	}
	
	/** Inits the new resource.
	 * @param name resource name
	 * @param format resource value format
	 * @param value resource value */
	private void init(String name, int format, byte[] value) {
		this.name=name;
		this.format=format;
		this.value=value;
	}
	
	/** Gets resource name.
	 * @return the name */
	public String getName() {
		return name;
	}
	/** Gets the resource value format.
	 * @return the format */
	public int getFormat() {
		return format;
	}
	
	/** Sets the resource value format.
	 * @param format resource value format */
	public void setFormat(int format) {
		this.format=format;
	}
	
	/** Gets resource value.
	 * @return the resource value */
	public byte[] getValue() {
		return value;
	}
	
	/** Sets resource value.
	 * @param value the resource value */
	public void setValue(byte[] value) {
		this.value=value;
	}
	
	/** Adds a request to observe the resource.
	 * @param req the request to be added */
	public void addObserveRequest(CoapRequest req) {
		observe_requests.add(req);
	}
	
	/** Removes a request to observe the resource.
	 * @param req the request to be removed */
	public void removeObserveRequest(CoapRequest req) {
		observe_requests.remove(req);
	}
	
	/** Gets an iterator of the requests to observe the resource.
	 * @return an iterator of requests */
	public Iterator<CoapRequest> getObserveRequestIterator() {
		return observe_requests.iterator();
	}
	
	@Override
	public String toString() {
		return "{\""+name+"\","+format+","+((format==ContentFormatOption.FORMAT_TEXT_PLAIN_UTF8 || format==ContentFormatOption.FORMAT_APP_XML || format==ContentFormatOption.FORMAT_APP_JSON || format==ContentFormatOption.FORMAT_APP_LINK_FORMAT)? '\"'+new String(value)+'\"' : ByteUtils.asHex(value))+"}";
	}

}
