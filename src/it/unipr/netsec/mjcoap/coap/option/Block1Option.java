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




/** CoAP Block1 options (RFC 7959).
 */
public class Block1Option extends BlockOption {
	

	/** Creates a new Block1 option.
	 * @param co CoapOption to be copied */
	public Block1Option(CoapOption co) {
		super(co);
	}

	/** Creates a new Block1 option.
	 * @param block_num the relative number of the block (NUM) within a sequence of blocks with the given size
	 * @param more_blocks whether more blocks are following (M)
	 * @param size_exp the 2-power exponent of the size of the block (equals to SZX + 4) */
	public Block1Option(long block_num, boolean more_blocks,int size_exp) {
		super(CoapOptionNumber.Block1,block_num,more_blocks,size_exp);
	}

}
