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

package it.unipr.netsec.mjcoap.coap.option;




/** CoAP Content-Format option (see RFC 7252).
 */
public class ContentFormatOption extends CoapOption {
	
	/** Format text/plain;charset=utf-8 */
	public static final int FORMAT_TEXT_PLAIN_UTF8=0;
	
	/** Format application/link-format */
	public static final int FORMAT_APP_LINK_FORMAT=40;
	
	/** Format application/xml */
	public static final int FORMAT_APP_XML=41;

	/** Format application/octet-stream */
	public static final int FORMAT_APP_OCTECT_STREAM=42;

	/** Format application/exi */
	public static final int FORMAT_APP_EXI=47;

	/** Format application/json */
	public static final int FORMAT_APP_JSON=50;

	
	/** Gets a string representation of a content-format.
	 * @param content_format content format identifier
	 * @return the string representation of the content-format */
	public static String getContentFormat(int content_format) {
		if (content_format<0) return null;
		// else
		switch (content_format) {
			case FORMAT_TEXT_PLAIN_UTF8 : return "text/plain;charset=utf-8";
			case FORMAT_APP_LINK_FORMAT : return "application/link-format";
			case FORMAT_APP_XML : return "application/xml";
			case FORMAT_APP_OCTECT_STREAM : return "application/octet-stream";
			case FORMAT_APP_EXI : return "application/exi";
			case FORMAT_APP_JSON : return "application/json";
		}
		// otherwise
		return "unknown";
	}
	
	
	/** Gets a content-format identifier.
	 * @param content_format the string representation of the content-format
	 * @return content format identifier */
	public static int getContentFormatIdentifier(String content_format) {
		if (content_format.equals("text/plain;charset=utf-8")) return FORMAT_TEXT_PLAIN_UTF8;
		else
		if (content_format.equals("application/link-format")) return FORMAT_APP_LINK_FORMAT;
		else
		if (content_format.equals("application/xml")) return FORMAT_APP_XML;
		else
		if (content_format.equals("application/octet-stream")) return FORMAT_APP_OCTECT_STREAM;
		else
		if (content_format.equals("application/exi")) return FORMAT_APP_EXI;
		else
		if (content_format.equals("application/json")) return FORMAT_APP_JSON;
		// otherwise
		if (content_format.equalsIgnoreCase("text") || content_format.equalsIgnoreCase("txt")) return FORMAT_TEXT_PLAIN_UTF8;
		else
	    if (content_format.equalsIgnoreCase("bin")) return FORMAT_APP_OCTECT_STREAM;
		else
		if (content_format.equalsIgnoreCase("xml")) return FORMAT_APP_XML;
		else
		if (content_format.equalsIgnoreCase("json")) return FORMAT_APP_JSON;
		// otherwise
		return -1;
	}
	
	
	/** Creates a new Content-Format option.
	 * @param co CoapOption to be copied */
	public ContentFormatOption(CoapOption co) {
		super(co);
	}


	/** Creates a new Content-Format option.
	 * @param contet_format content format identifier */
	public ContentFormatOption(int contet_format) {
		super(CoapOptionNumber.ContentFormat,contet_format);
	}


	/** Gets the content format identifier.
	 * @return the content format identifier */
	public int getContentFormatIdentifier() {
		return (int)getValueAsUnit();
	}

}
