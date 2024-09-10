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




/** CoAP response codes.
  */
public class CoapResponseCode {
	
	/** Response code "2.01 Created" */
	private static final int RESPONSE_2_01_Created=65;
	/** Response code "2.02 Deleted" */
	private static final int RESPONSE_2_02_Deleted=66;
	/** Response code "2.03 Valid" */
	private static final int RESPONSE_2_03_Valid=67;
	/** Response code "2.04 Changed" */
	private static final int RESPONSE_2_04_Changed=68;
	/** Response code "2.05 Content" */
	private static final int RESPONSE_2_05_Content=69;
	/** Response code "2.31 Continue" */
	private static final int RESPONSE_2_31_Continue=95;

	/** Response code "4.00 Bad Request" */
	private static final int RESPONSE_4_00_Bad_Request=128;
	/** Response code "4.01 Unauthorized" */
	private static final int RESPONSE_4_01_Unauthorized=129;
	/** Response code "4.02 Bad Option" */
	private static final int RESPONSE_4_02_Bad_Option=130;
	/** Response code "4.03 Forbidden" */
	private static final int RESPONSE_4_03_Forbidden=131;
	/** Response code "4.04 Not Found" */
	private static final int RESPONSE_4_04_Not_Found=132;
	/** Response code "4.05 Method Not Allowed" */
	private static final int RESPONSE_4_05_Method_Not_Allowed=133;
	/** Response code "4.06 Not Acceptable" */
	private static final int RESPONSE_4_06_Not_Acceptable=134;
	/** Response code "4.08 Request Entity Incomplete" */
	private static final int RESPONSE_4_08_Request_Entity_Incomplete=136;
	/** Response code "4.12 Precondition Failed" */
	private static final int RESPONSE_4_12_Precondition_Failed=140;
	/** Response code "4.13 Request Entity Too Large" */
	private static final int RESPONSE_4_13_Request_Entity_Too_Large=141;
	/** Response code "4.15 Unsupported Content-Format" */
	private static final int RESPONSE_4_15_Unsupported_ContentFormat=143;

	/** Response code "5.00 Internal Server Error" */
	private static final int RESPONSE_5_00_Internal_Server_Error=160;
	/** Response code "5.01 Not Implemented" */
	private static final int RESPONSE_5_01_Not_Implemented=161;
	/** Response code "5.02 Bad Gateway" */
	private static final int RESPONSE_5_02_Bad_Gateway=162;
	/** Response code "5.03 Service Unavailable" */
	private static final int RESPONSE_5_03_Service_Unavailable=163;
	/** Response code "5.04 Gateway Timeout" */
	private static final int RESPONSE_5_04_Gateway_Timeout=164;
	/** Response code "5.05 Proxing Not Supported" */
	private static final int RESPONSE_5_05_Proxing_Not_Supported=165;

	
	/** Response code "2.01 Created" */
	public static final CoapResponseCode _2_01_Created=new CoapResponseCode(RESPONSE_2_01_Created,"Created");
	/** Response code "2.02 Deleted" */
	public static final CoapResponseCode _2_02_Deleted=new CoapResponseCode(RESPONSE_2_02_Deleted,"Deleted");
	/** Response code "2.03 Valid" */
	public static final CoapResponseCode _2_03_Valid=new CoapResponseCode(RESPONSE_2_03_Valid,"Valid");
	/** Response code "2.04 Changed" */
	public static final CoapResponseCode _2_04_Changed=new CoapResponseCode(RESPONSE_2_04_Changed,"Changed");
	/** Response code "2.05 Content" */
	public static final CoapResponseCode _2_05_Content=new CoapResponseCode(RESPONSE_2_05_Content,"Content");
	/** Response code "2.31 Continue" */
	public static final CoapResponseCode _2_31_Continue=new CoapResponseCode(RESPONSE_2_31_Continue,"Continue");

	/** Response code "4.00 Bad Request" */
	public static final CoapResponseCode _4_00_Bad_Request=new CoapResponseCode(RESPONSE_4_00_Bad_Request,"Bad Request");
	/** Response code "4.01 Unauthorized" */
	public static final CoapResponseCode _4_01_Unauthorized=new CoapResponseCode(RESPONSE_4_01_Unauthorized,"Unauthorized");
	/** Response code "4.02 Bad Option" */
	public static final CoapResponseCode _4_02_Bad_Option=new CoapResponseCode(RESPONSE_4_02_Bad_Option,"Bad Option");
	/** Response code "4.03 Forbidden" */
	public static final CoapResponseCode _4_03_Forbidden=new CoapResponseCode(RESPONSE_4_03_Forbidden,"Forbidden");
	/** Response code "4.04 Not Found" */
	public static final CoapResponseCode _4_04_Not_Found=new CoapResponseCode(RESPONSE_4_04_Not_Found,"Not Found");
	/** Response code "4.05 Method Not Allowed" */
	public static final CoapResponseCode _4_05_Method_Not_Allowed=new CoapResponseCode(RESPONSE_4_05_Method_Not_Allowed,"Method Not Allowed");
	/** Response code "4.06 Not Acceptable" */
	public static final CoapResponseCode _4_06_Not_Acceptable=new CoapResponseCode(RESPONSE_4_06_Not_Acceptable,"Not Acceptable");
	/** Response code "4.08 Request Entity Incomplete" */
	public static final CoapResponseCode _4_08_Request_Entity_Incomplete=new CoapResponseCode(RESPONSE_4_08_Request_Entity_Incomplete,"Request Entity Incomplete");
	/** Response code "4.12 Precondition Failed" */
	public static final CoapResponseCode _4_12_Precondition_Failed=new CoapResponseCode(RESPONSE_4_12_Precondition_Failed,"Precondition Failed");
	/** Response code "4.13 Request Entity Too Large" */
	public static final CoapResponseCode _4_13_Request_Entity_Too_Large=new CoapResponseCode(RESPONSE_4_13_Request_Entity_Too_Large,"Request Entity Too Large");
	/** Response code "4.15 Unsupported Content-Format" */
	public static final CoapResponseCode _4_15_Unsupported_ContentFormat=new CoapResponseCode(RESPONSE_4_15_Unsupported_ContentFormat,"Unsupported Content-Format");

	/** Response code "5.00 Internal Server Error" */
	public static final CoapResponseCode _5_00_Internal_Server_Error=new CoapResponseCode(RESPONSE_5_00_Internal_Server_Error,"Internal Server Error");
	/** Response code "5.01 Not Implemented" */
	public static final CoapResponseCode _5_01_Not_Implemented=new CoapResponseCode(RESPONSE_5_01_Not_Implemented,"Not Implemented");
	/** Response code "5.02 Bad Gateway" */
	public static final CoapResponseCode _5_02_Bad_Gateway=new CoapResponseCode(RESPONSE_5_02_Bad_Gateway,"Bad Gateway");
	/** Response code "5.03 Service Unavailable" */
	public static final CoapResponseCode _5_03_Service_Unavailable=new CoapResponseCode(RESPONSE_5_03_Service_Unavailable,"Service Unavailable");
	/** Response code "5.04 Gateway Timeout" */
	public static final CoapResponseCode _5_04_Gateway_Timeout=new CoapResponseCode(RESPONSE_5_04_Gateway_Timeout,"5.04 Gateway Timeout");
	/** Response code "5.05 Proxing Not Supported" */
	public static final CoapResponseCode _5_05_Proxing_Not_Supported=new CoapResponseCode(RESPONSE_5_05_Proxing_Not_Supported,"5.05 Proxing Not Supported");

	
	/** Response description */
	private String description;

	/** Response code */
	private int code;
	
	
	/** Creates a new CoAP response code.
	 * @param code the response code
	 * @param description the response description */
	protected CoapResponseCode(int code, String description) {
		this.code=code;
		this.description=description;
	}

	/** Gets the response code.
	 * @return the code */
	public int getCode() {
		return code;
	}
  
	/** Gets the response code class.
	 * @return the class value */
	public int getCodeClass() {
		return (code>>5)&0x7;
	}

	/** Gets the response code detail.
	 * @return the detail value */
	public int getCodeDetail() {
		return code&0x1f;
	}

	/** Gets the response description.
	 * @return the description */
	public String getDescription() {
		return description;
	}
  
	/** Whether it is a success response code.
	 * @return <i>true</i> if success response code (2.x) */
	public boolean isSuccess() {
		return code>=64 && code<96;
	}

	/** Indicates whether another object is "equal to" this one. 
	 * @param obj the reference object with which to compare
	 * @return <i>true</i> if response codes are the same */
	@Override
	public boolean equals(Object obj) {
		if (obj==this) return true;
		// else
		if(obj instanceof CoapResponseCode) {
			CoapResponseCode response_code=(CoapResponseCode)obj;
			return response_code.code==this.code;
		}
		return false;
	}

	/** Gets a string representation of this object.
	 * @return the response code (code class and code detail separated by a dot) and description (e.g. "2.01 Created") */
	@Override
	public String toString() {
		StringBuffer sb=new StringBuffer();
		sb.append(getCodeClass()).append('.').append(getCodeDetail());
		if (description!=null) sb.append(' ').append(description);
		return sb.toString();
	}
	
	/** Composes the response code with a given code class and given detail.
	 * @param code_class the code class
	 * @param code_detail the code detail
	 * @return the specified response code */
	public static CoapResponseCode getResponseCode(int code_class, int code_detail) {
		return getResponseCode(((code_class&0x7)<<5) | (code_detail&0x1f));
	}

	/** Gets the response code with a given code.
	 * @param code the code
	 * @return the response code */
	public static CoapResponseCode getResponseCode(int code) {
		if (code<64) throw new RuntimeException("Invalid CoAP response code ("+code+")");
		// else
		if (code<96) {
			switch (code) {
				case RESPONSE_2_01_Created  : return _2_01_Created;
				case RESPONSE_2_02_Deleted  : return _2_02_Deleted;
				case RESPONSE_2_03_Valid    : return _2_03_Valid;
				case RESPONSE_2_04_Changed  : return _2_04_Changed;
				case RESPONSE_2_05_Content  : return _2_05_Content;
				case RESPONSE_2_31_Continue : return _2_31_Continue;
			}
		}
		// else
		if (code<160) {
			switch (code) {
				case RESPONSE_2_01_Created                   : return _2_01_Created;
				case RESPONSE_4_00_Bad_Request               : return _4_00_Bad_Request;
				case RESPONSE_4_01_Unauthorized              : return _4_01_Unauthorized;
				case RESPONSE_4_02_Bad_Option                : return _4_02_Bad_Option;
				case RESPONSE_4_03_Forbidden                 : return _4_03_Forbidden;
				case RESPONSE_4_04_Not_Found                 : return _4_04_Not_Found;
				case RESPONSE_4_05_Method_Not_Allowed        : return _4_05_Method_Not_Allowed;
				case RESPONSE_4_06_Not_Acceptable            : return _4_06_Not_Acceptable;
				case RESPONSE_4_08_Request_Entity_Incomplete : return _4_08_Request_Entity_Incomplete;
				case RESPONSE_4_12_Precondition_Failed       : return _4_12_Precondition_Failed;
				case RESPONSE_4_13_Request_Entity_Too_Large  : return _4_13_Request_Entity_Too_Large;
				case RESPONSE_4_15_Unsupported_ContentFormat : return _4_15_Unsupported_ContentFormat;
			}
		}
		// else
		else {
			switch (code) {
				case RESPONSE_5_00_Internal_Server_Error : return _5_00_Internal_Server_Error;
				case RESPONSE_5_01_Not_Implemented       : return _5_01_Not_Implemented;
				case RESPONSE_5_02_Bad_Gateway           : return _5_02_Bad_Gateway;
				case RESPONSE_5_03_Service_Unavailable   : return _5_03_Service_Unavailable;
				case RESPONSE_5_04_Gateway_Timeout       : return _5_04_Gateway_Timeout;
				case RESPONSE_5_05_Proxing_Not_Supported : return _5_05_Proxing_Not_Supported;
			}
		}
		// else
		return new CoapResponseCode(code,null);
	}

}
