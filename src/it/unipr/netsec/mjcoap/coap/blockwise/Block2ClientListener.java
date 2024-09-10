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

package it.unipr.netsec.mjcoap.coap.blockwise;


import it.unipr.netsec.mjcoap.coap.message.CoapResponse;


/** Listens for client-side blockwise transfer events.
 */
interface Block2ClientListener {
	
	/** When a complete CoAP response message is received.
	 * @param block2_client the blockwise transfer client
	 * @param msg the received CoAP response */
	public void onReceivedResponse(Block2Client block2_client, CoapResponse resp);

	/** When a RST is received for a Confirmable request or transaction timeout expired.
	 * @param block2_client the block2 client */
	public void onBlock2ClientFailure(Block2Client block2_client);
}
