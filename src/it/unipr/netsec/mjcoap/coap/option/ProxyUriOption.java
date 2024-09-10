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




/** CoAP Proxy-Uri option (see RFC 7252).
 */
public class ProxyUriOption extends CoapOption {
	

	/** Creates a new Proxy-Uri option.
	 * @param co CoapOption to be copied */
	public ProxyUriOption(CoapOption co) {
		super(co);
	}


	/** Creates a new Proxy-Uri option.
	 * @param uri the URI */
	public ProxyUriOption(String uri) {
		super(CoapOptionNumber.ProxyUri,uri);
	}


	/** Gets the URI.
	 * @return the URI */
	public String getURI() {
		return getValueAsString();
	}

}
