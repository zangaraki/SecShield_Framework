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




/** CoAP If-Match option (see RFC 7252).
 */
public class IfMatchOption extends CoapOption {
	
  
	/** Creates a new If-Match option.
	 * @param co CoapOption to be copied */
	public IfMatchOption(CoapOption co) {
		super(co);
	}


	/** Creates a new If-Match option. */
	public IfMatchOption() {
		super(CoapOptionNumber.IfMatch,EMPTY);
	}


	/** Creates a new If-Match option.
	 * @param entity_tag an entity-tag */
	public IfMatchOption(String entity_tag) {
		super(CoapOptionNumber.IfMatch,entity_tag);
	}


	/** Gets the If-Match value.
	 * @return the an empty string or an entity-tag */
	public byte[] getIfMatchValue() {
		return getValueAsOpaque();
	}

}
