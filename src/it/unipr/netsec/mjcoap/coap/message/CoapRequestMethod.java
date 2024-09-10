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




/** CoAP request methods (GET, POST, PUT, DELETE).
  */
public class CoapRequestMethod {
	
	/** GET code */
	private static final int METHOD_GET=1;
	/** POST code */
	private static final int METHOD_POST=2;
	/** PUT code */
	private static final int METHOD_PUT=3;
	/** DELETE code */
	private static final int METHOD_DELETE=4;
	
	/** GET request method */
	public static final CoapRequestMethod GET=new CoapRequestMethod(METHOD_GET,"GET");
	/** POST request method */
	public static final CoapRequestMethod POST=new CoapRequestMethod(METHOD_POST,"POST");
	/** PUT request method */
	public static final CoapRequestMethod PUT=new CoapRequestMethod(METHOD_PUT,"PUT");
	/** DELETE request method */
	public static final CoapRequestMethod DELETE=new CoapRequestMethod(METHOD_DELETE,"DELETE");

	
	/** Method name */
	private String name;

	/** Method code */
	private int code;
	
	
	/** Creates a new CoAP request method.
	 * @param code the method code
	 * @param name the method name */
	protected CoapRequestMethod(int code, String name) {
		this.code=code;
		this.name=name;
	}
	
	/** Gets the method code.
	 * @return the code */
	public int getCode() {
		return code;
	}
  
	/** Gets the method name.
	 * @return the name */
	public String getName() {
		return name;
	}
  
	/** Indicates whether another object is "equal to" this one. 
	 * @param obj the reference object with which to compare
	 * @return <i>true</i> if the method codes are the same */
	@Override
	public boolean equals(Object obj) {
		if (obj==this) return true;
		// else
		if(obj instanceof CoapRequestMethod) {
			CoapRequestMethod method=(CoapRequestMethod)obj;
			return method.code==this.code;
		}
		return false;
	}

	/** Gets a string representation of this object.
	 * @return the method name */
	@Override
	public String toString() {
		return getName();
	}

	/** Gets request method from method name.
	  * @return the request method (1=GET, 2=POST, 3=PUT, 4=DELETE) */
	public static CoapRequestMethod getMethodByName(String method_name) {
		if (method_name.equalsIgnoreCase("GET")) return GET;
		// else
		if (method_name.equalsIgnoreCase("POST")) return POST;
		// else
		if (method_name.equalsIgnoreCase("PUT")) return PUT;
		// else
		if (method_name.equalsIgnoreCase("DELETE")) return DELETE;
		// else
		return null;
	}

	/** Gets request method by code.
	 * @return the request method (GET, POST,  PUT, DELETE) */
	public static CoapRequestMethod getMethodByCode(int code) {
		switch(code) {
			case METHOD_GET    : return GET;
			case METHOD_POST   : return POST;
			case METHOD_PUT    : return PUT;
			case METHOD_DELETE : return DELETE;
		}
		// else
		return null;
	}

}
