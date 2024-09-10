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

package it.unipr.netsec.mjcoap.coap.message;




/** CoAP message types (CON=Confirmable (0), NON=Non-Confirmable (1), ACK=Acknowledgement (2), RST=Reset (3)).
  */
public class CoapMessageType {
	
	/** Message type CON=Confirmable (0) */
	private static final short TYPE_CON=(short)0;
	/** Message type NON=Non-Confirmable (1) */
	private static final short TYPE_NON=(short)1;
	/** Message type ACK=Acknowledgement (2) */
	private static final short TYPE_ACK=(short)2;
	/** Message type RST=Reset (3) */
	private static final short TYPE_RST=(short)3;
	
	/** Message type CON=Confirmable (0) */
	public static final CoapMessageType CON=new CoapMessageType(TYPE_CON,"CON");
	/** Message type NON=Non-Confirmable (1) */
	public static final CoapMessageType NON=new CoapMessageType(TYPE_NON,"NON");
	/** Message type ACK=Acknowledgement (2) */
	public static final CoapMessageType ACK=new CoapMessageType(TYPE_ACK,"ACK");
	/** Message type RST=Reset (3) */
	public static final CoapMessageType RST=new CoapMessageType(TYPE_RST,"RST");

	
	/** Type code */
	private short code;

	/** Type name */
	private String name;
	
	
	/** Creates a new CoAP message type.
	 * @param code type code
	 * @param name type name */
	protected CoapMessageType(short code, String name) {
		this.code=code;
		this.name=name;
	}
	
	/** Gets the type code.
	 * @return the type code */
	public short getCode() {
		return code;
	}
  
	/** Gets the type name.
	 * @return the type name */
	public String getName() {
		return name;
	}
  
	/** Indicates whether another object is "equal to" this one. 
	 * @param obj the reference object with which to compare
	 * @return <i>true</i> if the type codes are the same */
	@Override
	public boolean equals(Object obj) {
		if (obj==this) return true;
		// else
		if(obj instanceof CoapMessageType) {
			CoapMessageType type=(CoapMessageType)obj;
			return type.code==this.code;
		}
		return false;
	}

	/** Gets a string representation of this object.
	 * @return the type name */
	@Override
	public String toString() {
		return getName();
	}

	/** Gets message type from type name.
	  * @return the message type (CON=0, NON=1, ACK=2, RST=3) */
	public static CoapMessageType getMessageTypeByName(String type_name) {
		if (type_name.equalsIgnoreCase("CON")) return CON;
		// else
		if (type_name.equalsIgnoreCase("NON")) return NON;
		// else
		if (type_name.equalsIgnoreCase("ACK")) return ACK;
		// else
		if (type_name.equalsIgnoreCase("RST")) return RST;
		// else
		return null;
	}

	/** Gets message type from type code.
	 * @return the message type (CON=0, NON=1, ACK=2, RST=3) */
	public static CoapMessageType getMessageTypeByCode(int code) {
		switch(code) {
			case TYPE_CON : return CON;
			case TYPE_NON : return NON;
			case TYPE_ACK : return ACK;
			case TYPE_RST : return RST;
		}
		// else
		return null;
	}

}
