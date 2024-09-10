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




/** Collection of CoAP option numbers.
  */
public class CoapOptionNumber {
	
	// Basic options (RFC 7252):
	
	/** Option Reserved */
	public static final int reserved=0;

	/** Option If-Match */
	public static final int IfMatch=1;

	/** Option Uri-Host */
	public static final int UriHost=3;

	/** Option ETag */
	public static final int ETag=4;

	/** Option If-None-Match */
	public static final int IfNoneMatch=5;

	/** Option Uri-Port */
	public static final int UriPort=7;

	/** Option Location-Path */
	public static final int LocationPath=8;

	/** Option Uri-Path */
	public static final int UriPath=11;

	/** Option Content-Format */
	public static final int ContentFormat=12;

	/** Option Max-Age */
	public static final int MaxAge=14;

	/** Option Uri-Query */
	public static final int UriQuery=15;

	/** Option Accept */
	public static final int Accept=16;

	/** Option Location-Query */
	public static final int LocationQuery=20;

	/** Option Proxy-Uri */
	public static final int ProxyUri=35;

	/** Option Proxy-Scheme */
	public static final int ProxyScheme=39;

	/** Option Size1 */
	public static final int Size1=60;

	// Blockwise transfer options (RFC 7959-15):

	/** Block2 */
	public static final int Block2=23;

	/** Block1 */
	public static final int Block1=27;
	
	/** Size2 */
	public static final int Size2=28;

	// Observing Resources options (RFC 7641-14):

	/** Observe */ 
	public static final int Observe=6;

	
	
	/** Gets option name. */
	public static String getOptionName(int number) {
		switch (number) {
			// RFC 7252:
			case  reserved : return "reserved";
			case  IfMatch : return "If-Match";
			case  UriHost : return "Uri-Host";
			case  ETag : return "ETag";
			case  IfNoneMatch : return "If-None-Match";
			case  UriPort : return "Uri-Port";
			case  LocationPath : return "Location-Path";
			case  UriPath : return "Uri-Path";
			case  ContentFormat : return "Content-Format";
			case  MaxAge : return "Max-Age";
			case  UriQuery : return "Uri-Query";
			case  Accept : return "Accept";
			case  LocationQuery : return "Location-Query";
			case  ProxyUri : return "Proxy-Uri";
			case  ProxyScheme : return "Proxy-Scheme";
			case  Size1 : return "Size1";
			
			// RFC 7959-15:
			case  Block2 : return "Block2";
			case  Block1 : return "Block1";
			case  Size2 : return "Size2";
			
			// RFC 7641-14:
			case  Observe : return "Observe";
		}
		// else
		return "unknown";
	} 


	/** Whether it is a Critical option number.
	  * @return true if Critical option number */
	public static boolean isCritical(int number) {
		return (number&0x1)==0x1;
	}


	/** Whether it is a UnSafe option number.
	  * @return true if UnSafe option number */
	public static boolean isUnSafe(int number) {
		return (number&0x2)==0x2;
	}


	/** Whether it is a NoCacheKey option number.
	  * @return true if NoCacheKey option number */
	public static boolean isNoCacheKey(int number) {
		return (number&0x1e)==0x1c;
	}

}
