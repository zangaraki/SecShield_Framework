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




/** CoAP Block-type option (RFC 7959).
 */
abstract class BlockOption extends CoapOption {
	

	/** Creates a new abstract Block option.
	 * @param co CoapOption to be copied */
	protected BlockOption(CoapOption co) {
		super(co);
	}

	/** Creates a new abstract Block option.
	 * @param opt_number the option number
	 * @param block_num the relative number of the block (NUM) within a sequence of blocks with the given size
	 * @param more_blocks whether more blocks are following (M)
	 * @param szx the 2-power exponent of the size of the block, minus 4 (SZX) */
	protected BlockOption(int opt_number, long block_num, boolean more_blocks, short szx) {
		super(opt_number,(block_num<<4)|(more_blocks?0x8:0x0)|(szx&0x7));
	}


	/** Creates a new abstract Block option.
	 * @param opt_number the option number
	 * @param size the size of the block (it is equal to 2**(SZX + 4))
	 * @param more_blocks whether more blocks are following (M)
	 * @param block_num the relative number of the block (NUM) within a sequence of blocks with the given size */
	protected BlockOption(int opt_number, long block_num, boolean more_blocks, int size) {
		super(opt_number,(block_num<<4)|(more_blocks?0x8:0x0)|sizeToSzx(size));
	}


	/** Gets SZX, that is the 2-power exponent of the size of the block minus 4.
	 * @return the SZX value */
	public int getSZX() {
		return (int)getValueAsUnit()&0x7;
	}


	/** Gets the size of the block.
	 * @return the size */
	public int getSize() {
		return szxToSize((short)(getValueAsUnit()&0x7));
	}


	/** Whether there are more blocks (flag M).
	 * @return <i>true</i> if there are more blocks (that is if flag M equals to 1) */
	public boolean moreBlocks() {
		return (getValueAsUnit()&0x8)==8;
	}


	/** Gets the block sequence number.
	 * @return the block sequence number */
	public long getSequenceNumber() {
		return getValueAsUnit()>>4;
	}

	
	/** SZX to size.
	 * @param szx the szx value
	 * @return the size */
	private static int szxToSize(short szx) {
		return 16<<(szx&0x7);
	}


	/** Size to SZX.
	* @param size the size
	* @return SZX */
	private static short sizeToSzx(int size) {
		/*if (size<=16) return 0;
		if (size<=32) return 1;
		if (size<=64) return 2;
		if (size<=128) return 3;
		if (size<=256) return 4;
		if (size<=512) return 5;
		if (size<=1024) return 6;
		throw new RuntimeException("sizeToSzx(): size ("+size+") too big for SZX");*/
		switch (size) {
			case 16 : return 0;
			case 32 : return 1;
			case 64 : return 2;
			case 128 : return 3;
			case 256 : return 4;
			case 512 : return 5;
			case 1024 : return 6;
		}
		if (size>1024) throw new RuntimeException("sizeToSzx(): size too big: "+size);
		else throw new RuntimeException("sizeToSzx(): size must be a power of 2: "+size);
	}

}
