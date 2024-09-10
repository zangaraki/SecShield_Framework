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

package it.unipr.netsec.mjcoap.coap.option;


import it.unipr.netsec.mjcoap.coap.message.CoapMessageFormatException;


/** CoAP option.
  * CoAP defines a number of options which can be included in a message.
  * Each option instance in a message specifies the Option Number of the
  * defined CoAP option, the length of the Option Value and the Option
  * Value itself.
  */
public class CoapOption implements Comparable {
	
	/** Empty value */
	public static byte[] EMPTY=new byte[0];

	
	/** Option number */
	protected int number;
	
	/** Option value */
	protected byte[] value;

	/** Option value buffer */
	//protected byte[] buf;

	/** Option value offset */
	//protected int off;

	/** Option value length */
	//protected int len;



	/** Creates a new CoapOption. */
	private CoapOption() {
		number=0;
		//off=len=0;
		//buf=null;
		value=null;
	}


	/** Creates a new CoapOption.
	  * @param co CoapOption to be copied */
	public CoapOption(CoapOption co) {
		//init(co.number,co.buf,co.off,co.len);
		init(co.number,co.value,0,co.value==null? 0 : co.value.length);
	}


	/** Creates a new opaque CoapOption.
	  * @param number option number
	  * @param buf buffer containing the opaque option value
	  * @param off offset within the buffer
	  * @param len value length */
	public CoapOption(int number, byte[] buf, int off, int len) {
		init(number,buf,off,len);
	}


	/** Creates a new opaque CoapOption.
	  * @param number option number
	  * @param value opaque value */
	public CoapOption(int number, byte[] value) {
		init(number,value,0,value.length);
	}


	/** Creates a new string CoapOption.
	  * @param number option number
	  * @param value_str the string */
	public CoapOption(int number, String value_str) {
		byte[] value_bytes=value_str.getBytes();
		init(number,value_bytes,0,value_bytes.length);
	}


	/** Creates a new unit CoapOption with fixed size.
	  * @param number option number
	  * @param value_unit the unit */
	public CoapOption(int number, long value_unit) {
		int value_len=0;
		for (long i=value_unit; i!=0; i>>=8) value_len++;
		init(number,value_unit,value_len);
	}


	/** Creates a new unit CoapOption with fixed size.
	  * @param number option number
	  * @param value_unit the unit
	  * @param value_len length of the unit (in bytes) */
	public CoapOption(int number, long value_unit, int value_len) {
		init(number,value_unit,value_len);
	}


	/** Initializes a unit CoapOption.
	  * @param number option number
	  * @param value_unit the unit
	  * @param value_len length of the unit (in bytes) */
	private void init(int number, long value_unit, int value_len) {
		byte[] value_bytes=new byte[value_len];
		for (int i=value_len-1; i>=0; i--) {
			value_bytes[i]=(byte)(value_unit&0xff);
			value_unit>>=8;
		}
		init(number,value_bytes,0,value_len);
	}

	
	/** Initializes the CoapOption.
	  * @param number option number
	  * @param buf buffer containing the option value
	  * @param off offset within the buffer
	  * @param len value len */
	private void init(int number, byte[] buf, int off, int len) {
		this.number=number;
		//this.buf=buf;
		//this.off=off;
		//this.len=len;
		if (len>0) {
			this.value=new byte[len];
			System.arraycopy(buf,off,value,0,len);
		}
	}


	/** Gets a CoapOption from a byte array.
	  * @param prev_opt_num previous option number
	  * @param data the byte array containing the option 
	  * @return a new CoapOption */
	public static CoapOption parseCoapOption(int prev_opt_num, byte[] data) throws CoapMessageFormatException {
		CoapOption opt=new CoapOption();
		opt.init(prev_opt_num,data,0);
		return opt;
	}


	/** Gets a CoapOption from a byte array.
	  * @param prev_opt_num previous option number
	  * @param buf byte buffer containing the option
	  * @param off offset within the buffer
	  * @return a new CoapOption */
	public static CoapOption parseCoapOption(int prev_opt_num, byte[] buf, int off) throws CoapMessageFormatException {
		CoapOption opt=new CoapOption();
		opt.init(prev_opt_num,buf,off);
		return opt;
	}


	/** Inits the CoapOption.
	  * @param prev_opt_num previous option number
	  * @param buf buffer containing the option
	  * @param off offset within the buffer */
	private void init(int prev_opt_num, byte[] buf, int off) throws CoapMessageFormatException {
		int index=off;
		
		int delta=(buf[index]>>4)&0xf;
		int value_len=buf[index]&0xf;
		index++;

		if (delta==13) delta=13+(buf[index++]&0xff);
		else
		if (delta==14) {  delta=(269+(buf[index]&0xff)<<8)+(buf[index+1]&0xff); index+=2;  }
		else
		if (delta==15) throw new CoapMessageFormatException("invalid option delta ("+delta+")");
		//this.number=prev_opt_num+delta;
		int option_number=prev_opt_num+delta;

		if (value_len==13) value_len=13+(buf[index++]&0xff);
		else
		if (value_len==14) {  value_len=(269+(buf[index]&0xff)<<8)+(buf[index+1]&0xff); index+=2;  } 
		else
		if (value_len==15) throw new CoapMessageFormatException("invalid option value length ("+value_len+")");
		//this.buf=buf;
		//this.off=index;
		//this.len=value_len;
		init(option_number,buf,index,value_len);
	}


	/** From interface Comparable. Compares this object with the specified object for order.
	  * @param o the Object to be compared 
	  * @return a negative integer, zero, or a positive integer as this object is less than, equal to, or greater than the specified object */
	public int compareTo(Object o) throws ClassCastException {
		CoapOption opt=(CoapOption)o;
		return number-opt.number;
	}


	/** Gets the option number.
	  * @return the option number */
	public int getOptionNumber() {
		return number;
	}


	/** Gets the option name.
	  * @return the option name */
	/*public String getName() {
		return CoapOptionNumber.getOptionName(number);
	}*/


	/** Whether it is a Critical option.
	  * @return true if Critical option */
	public boolean isCritical() {
		return (number&0x1)==0x1;
	}


	/** Whether it is a UnSafe option.
	  * @return true if UnSafe option */
	public boolean isUnSafe() {
		return (number&0x2)==0x2;
	}


	/** Whether it is a NoCacheKey option.
	  * @return true if NoCacheKey option */
	public boolean isNoCacheKey() {
		return (number&0x1e)==0x1c;
	}


	/** Whether it is empty.
	  * @return true if empty option */
	public boolean isEmpty() {
		//return len==0;
		return value==null || value.length==0;
	}


	/** Gets the value length.
	  * @return the length of the option value */
	/*public int getValueLength() {
		return len;
	}*/


	/** Gets the option value as opaque byte array.
	  * @return the option value */
	public byte[] getValueAsOpaque() {
		/*if (len==0) return null;
		// else
		if (off==0 && len==buf.length) return buf;
		// else
		byte[] value=new byte[len];
		getValueAsOpaque(value,0);*/
		return value;
	}


	/** Gets the option value as opaque byte array.
	  * @param buf the buffer where the value has to be written
	  * @param off the offset within the buffer
	  * @return the length of the value */
	public int getValueAsOpaque(byte[] buf, int off) {
		//if (len==0) return 0;
		if (isEmpty()) return 0;
		// else
		//System.arraycopy(this.buf,this.off,buf,off,len);
		System.arraycopy(value,0,buf,off,value.length);
		return value.length;
	}


	/** Gets the option value as string.
	  * @return the option value as string */
	public String getValueAsString() {
		//if (len==0) return null;
		if (isEmpty()) return null;
		// else
		//return new String(buf,off,len);
		return new String(value);
	}


	/** Gets the option value as integer.
	  * @return the option value as long integer */
	public long getValueAsUnit() {
		//if (len==0) return 0;
		if (isEmpty()) return 0;
		// else
		long unit=0;
		//for (int i=0; i<len; i++) unit=(unit<<8)+(buf[off+i]&0xff);
		for (int i=0; i<value.length; i++) unit=(unit<<8)+(value[i]&0xff);
		return unit;
	}


	/** Gets the option length.
	  * @return the option length */
	public int getLength(int prev_opt_num) {
		int delta=number-prev_opt_num;
		if (delta<0) return 0;
		// else
		int len=value==null? 0 : value.length;
		int data_len=1+len;
		if (delta>12) data_len++;
		if (delta>268) data_len++;
		if (len>12) data_len++;
		if (len>268) data_len++;
		return data_len;
	}


	/** Gets bytes.
	  * @param prev_opt_num previous option number
	  * @return the byte array containing the option */
	public byte[] getBytes(int prev_opt_num) {
		byte[] data=new byte[getLength(prev_opt_num)];
		getBytes(prev_opt_num,data,0);
		return data;
	}


	/** Gets bytes.
	  * @param prev_opt_num previous option number
	  * @param buf the buffer where the option is going to be written
	  * @param off the offset within the buffer
	  * @return the length of the option */
	public int getBytes(int prev_opt_num, byte[] buf, int off) {
		int delta=number-prev_opt_num;
		int length=value==null? 0 : value.length;
		if (delta<0) return 0;
		// else
		int i=off;
		buf[i++]=(byte)((((delta<13)? delta : (delta<269)? 13 : 14)<<4) | ((length<13)? length : (length<269)? 13 : 14));
		if (delta>=269) {
			delta-=269;
			buf[i++]=(byte)((delta>>8)&0xff);
			buf[i++]=(byte)(delta&0xff);
		}
		else
		if (delta>=13) {
			delta-=13;
			buf[i++]=(byte)delta;
		}
		if (length>=269) {
			length-=269;
			buf[i++]=(byte)((length>>8)&0xff);
			buf[i++]=(byte)(length&0xff);
		}
		else
		if (length>=13) {
			length-=13;
			buf[i++]=(byte)length;
		}
		return i-off+getValueAsOpaque(buf,i);
	}

}
