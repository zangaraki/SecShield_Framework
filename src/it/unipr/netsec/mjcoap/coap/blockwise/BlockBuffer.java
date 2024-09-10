/*
 * Copyright (c) 2018 NetSec Lab - University of Parma
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


import java.util.Vector;


/** A buffer for composing fixed-size blocks of bytes (except for the last one).
 */
class BlockBuffer {
	
	/** Empty block */
	static final byte[] EMPTY_BLOCK=new byte[0];
	
	/** Total size */
	//int total_size=0;

	/** Number of blocks */
	int count=0;

	
	
	/** Block buffer */
	Vector<byte[]> block_buffer=new Vector<byte[]>();
	
	
	/** Creates a new BlockBuffer.
	 * @param block_size block size */
	public BlockBuffer() {
		
	}

	
	/** Adds a new block.
	 * @param block_size block size
	 * @return this object */
	public BlockBuffer addBlock(byte[] block) {
		if (block==null) throw new RuntimeException("BlockBuffer: null block");
		// else
		block_buffer.addElement(block);
		if (block!=EMPTY_BLOCK) count++;
		return this;
	}

	
	/** Sets a new block at a given position.
	 * @param block_size block size
	 * @param index block index
	 * @return this object */
	public BlockBuffer setBlockAt(byte[] block, int index) {
		if (block==null) throw new RuntimeException("BlockBuffer: null block");
		// else
		while (index>block_buffer.size()) block_buffer.addElement(EMPTY_BLOCK);
		if (index==block_buffer.size()) {
			if (block!=EMPTY_BLOCK) count++;
			block_buffer.addElement(block);
		}
		else {
			if (block_buffer.elementAt(index)!=EMPTY_BLOCK) count--;
			if (block!=EMPTY_BLOCK) count++;
			block_buffer.setElementAt(block,index);
		}
		return this;
	}
	
	
	/** Gets number of non-empty blocks.
	 * return the number of blocks */
	public int getNumberOfBlocks() {
		return count;
	}

	
	/** Gets the current buffer size in terms of empty and non-empty blocks.
	 * return the current size */
	public int size() {
		return block_buffer.size();
	}

	
	/** Whether the buffer is full.
	 * That is if the number of non-empty blocks equals the current size of the buffer. 
	 * return <i>true</i> if the buffer is full */
	public boolean isFull() {
		return block_buffer.size()==count;
	}

	
	/** Gets all blocks.
	 * return an array of blocks */
	public byte[][] getBlocks() {
		return block_buffer.toArray(new byte[block_buffer.size()][]);
	}

	
	/** Gets all bytes.
	 * return an array of all bytes */
	public byte[] getBytes() {
		int total_size=0;
		for (int i=0; i<block_buffer.size(); i++) total_size+=block_buffer.elementAt(i).length;
		byte[] data=new byte[total_size];
		int index=0;
		for (int i=0; i<block_buffer.size(); i++) {
			byte[] block_i=block_buffer.elementAt(i);
			for (int k=0; k<block_i.length; k++) data[index++]=block_i[k];
		}
		return data;
	}

}
