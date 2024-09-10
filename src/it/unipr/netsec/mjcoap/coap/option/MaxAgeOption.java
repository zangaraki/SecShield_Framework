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




/** CoAP Max-Age option (see RFC 7252).
 */
public class MaxAgeOption extends CoapOption {
	

	/** Creates a new MaxAgeOption.
	 * @param co CoapOption to be copied */
	public MaxAgeOption(CoapOption co) {
		super(co);
	}


	/** Creates a new MaxAgeOption.
	 * @param max_time the maximum time a response may be cached before it is considered not fresh */
	public MaxAgeOption(int max_time) {
		super(CoapOptionNumber.MaxAge,max_time);
	}


	/** Gets the maximum time a response may be cached before it is considered not fresh.
	 * @return the maximum time */
	public int getMaximumTime() {
		return (int)getValueAsUnit();
	}

}
