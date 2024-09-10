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


import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.zoolu.net.InetAddrUtils;


/** CoAP socket address.
 * If the port number is not specified, default port is used.
 */
public class CoapSocketAddress extends InetSocketAddress {

	public CoapSocketAddress(InetAddress ipaddr, int port) {
		super(ipaddr,port>=0? port: CoapProvider.DEFAUL_PORT);
	}

	public CoapSocketAddress(String addr, int port) {
		super(addr,port>=0? port: CoapProvider.DEFAUL_PORT);
	}

	public CoapSocketAddress(String str) throws IOException {
		this(parseInetSocketAddress(str));
	}

	public CoapSocketAddress(InetSocketAddress inetsoaddr) {
		super(inetsoaddr.getAddress(),inetsoaddr.getPort());
	}
	
	@Override
	public String toString() {
		return (getAddress()!=null? getAddress().getHostAddress(): "null")+':'+getPort();
	}

	
	private static InetSocketAddress parseInetSocketAddress(String str) throws IOException {
		try {
			return InetAddrUtils.parseInetSocketAddress(str);
		}
		catch (IllegalArgumentException e) {
			return new InetSocketAddress(InetAddress.getByName(str),CoapProvider.DEFAUL_PORT);
		}
	}
	
}
