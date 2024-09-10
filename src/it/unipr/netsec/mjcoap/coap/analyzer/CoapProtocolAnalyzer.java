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

package it.unipr.netsec.mjcoap.coap.analyzer;


import MyProject.CoapMessage;
import org.zoolu.util.ByteUtils;
//import java.util.Set;
//import java.util.Iterator;

import it.unipr.netsec.mjcoap.coap.message.*;
import it.unipr.netsec.mjcoap.coap.option.*;


/** CoAP protocol analyzer.
  */
public class CoapProtocolAnalyzer {
	
	/** Debug mode */
	//static final boolean DEBUG=true; 


	/** Creates a new CoapProtocolAnalyzer */
	private CoapProtocolAnalyzer() {}


	/** Analyzes a CoAP message.
	  * @param msg the CoAP message to be analyzed */
	public static ProtocolField analyze(CoapMessage msg) {
		
		//ProtocolField field=new ProtocolField(getMessageDescription(msg));
		ProtocolField field=new ProtocolField(getMessageDescription(msg));
		CoapMessageType type=msg.getType();
		field.addSubField("Type: "+type.getCode()+" ("+type.getName()+")");
		int code=msg.getCode();
		field.addSubField("Code: "+code+" ("+getCodeDescription(code)+")");
		field.addSubField("MessageID: "+msg.getMessageId()+" (0x"+Integer.toHexString(msg.getMessageId())+")");
		byte[] token=msg.getToken();
		field.addSubField("Token: "+(token!=null? "0x"+ByteUtils.asHex(token) : "none"));
		//Vector options=msg.getOptions();
		CoapOption[] options=msg.getOptions();
		if (options!=null && options.length>0) {
			StringBuffer sb=new StringBuffer();
			sb.append(options[0].getOptionNumber());
			for (int i=1; i<options.length; i++) sb.append(',').append(options[i].getOptionNumber());
			ProtocolField options_field=new ProtocolField("Options: "+sb.toString());
			//for (int i=0; i<options.size(); i++) options_field.addSubField(analyze((CoapOption)options.elementAt(i)));
			for (int i=0; i<options.length; i++) options_field.addSubField(analyze(options[i]));
			field.addSubField(options_field);
		}
		else field.addSubField("Options: none");
		byte[] payload=msg.getPayload();
		//field.addSubField("Payload: "+(payload!=null? "0x"+ByteUtils.asHex(payload) : "none"));
		field.addSubField(analyzePayload(payload));
		return field;
	}


	/** Analyzes a CoAP message payload.
	 * @param payload the CoAP message payload */
  private static ProtocolField analyzePayload(byte[] payload)
  {  ProtocolField field=new ProtocolField("Payload: "+(payload!=null? "0x"+ByteUtils.asHex(payload) : "none"));
	  //ProtocolField field=new ProtocolField("Payload: "+(payload!=null? payload.length : "0")+"B");
	  //field.addSubField("Bytes: "+(payload!=null? "0x"+ByteUtils.asHex(payload) : "none"));
	  field.addSubField("ASCII: "+(payload!=null? ByteUtils.asAscii(payload) : "none"));
	  return field;
  }


	/** Analyzes a CoAP message option.
	  * @param opt the CoAP message option to be analyzed */
	public static ProtocolField analyze(CoapOption opt) {
		//ProtocolField field=new ProtocolField("Option: "+opt.getOptionNumber()+" ("+opt.getName()+")");
		int opt_num=opt.getOptionNumber();
		byte[] opt_bytes=opt.getValueAsOpaque();
		int opt_len=opt_bytes!=null? opt_bytes.length : 0;
		//ProtocolField field=new ProtocolField("Option: "+opt_num+" ("+CoapOptionNumber.getOptionName(opt_num)+") "+(opt_bytes!=null?"0x"+ByteUtils.asHex(opt_bytes):"empty"));
		ProtocolField field=new ProtocolField("Option: "+opt_num+" ("+CoapOptionNumber.getOptionName(opt_num)+"): "+analyzeOptionValue(opt));
		field.addSubField("Number: "+opt.getOptionNumber());
		field.addSubField("Critical: "+(opt.isCritical()? "yes" : "no"));
		field.addSubField("UnSafe: "+(opt.isUnSafe()? "yes" : "no"));
		field.addSubField("NoCacheKey: "+(opt.isNoCacheKey()? "yes" : "no"));
		field.addSubField("ValueLen: "+opt_len);
		//byte[] value=opt.getValue();
		//field.addSubField("Value: "+(opt_len>0? "0x"+CoapMessage.asHex(value) : "empty"));
		//field.addSubField("Value: "+analyzeOptionValue(opt));
		field.addSubField("Value: "+(opt_bytes!=null?"0x"+ByteUtils.asHex(opt_bytes):"empty"));
		return field;
	}


	private static String analyzeOptionValue(CoapOption opt) {
		if (opt.getOptionNumber()==CoapOptionNumber.Accept) return String.valueOf(opt.getValueAsUnit());
		else
		if (opt.getOptionNumber()==CoapOptionNumber.ContentFormat) return String.valueOf(ContentFormatOption.getContentFormat((int)opt.getValueAsUnit()));
		else
		if (opt.getOptionNumber()==CoapOptionNumber.ETag) return "0x"+ByteUtils.asHex(opt.getValueAsOpaque());
		else
		if (opt.getOptionNumber()==CoapOptionNumber.IfMatch) return "0x"+ByteUtils.asHex(opt.getValueAsOpaque());
		else
		if (opt.getOptionNumber()==CoapOptionNumber.IfNoneMatch) return "";
		else
		if (opt.getOptionNumber()==CoapOptionNumber.LocationPath) return opt.getValueAsString();
		else
		if (opt.getOptionNumber()==CoapOptionNumber.LocationQuery) return opt.getValueAsString();
		else
		if (opt.getOptionNumber()==CoapOptionNumber.MaxAge) return String.valueOf(opt.getValueAsUnit());
		else
		if (opt.getOptionNumber()==CoapOptionNumber.ProxyScheme) return opt.getValueAsString();
		else
		if (opt.getOptionNumber()==CoapOptionNumber.ProxyUri) return opt.getValueAsString();
		else
		if (opt.getOptionNumber()==CoapOptionNumber.Size1) return String.valueOf(opt.getValueAsUnit());
		else
		if (opt.getOptionNumber()==CoapOptionNumber.UriHost) return opt.getValueAsString();
		else
		if (opt.getOptionNumber()==CoapOptionNumber.UriPath) return opt.getValueAsString();
		else
		if (opt.getOptionNumber()==CoapOptionNumber.UriPort) return String.valueOf(opt.getValueAsUnit());
		else
		if (opt.getOptionNumber()==CoapOptionNumber.UriQuery) return opt.getValueAsString();
		else
		if (opt.getOptionNumber()==CoapOptionNumber.Block1) {
			Block1Option o=new Block1Option(opt);
			return "seqn="+o.getSequenceNumber()+", more="+o.moreBlocks()+", size="+o.getSize();
		}
		else
		if (opt.getOptionNumber()==CoapOptionNumber.Block2) {
			Block2Option o=new Block2Option(opt);
			return "seqn="+o.getSequenceNumber()+", more="+o.moreBlocks()+", size="+o.getSize();
		}
		else
		if (opt.getOptionNumber()==CoapOptionNumber.Observe) return String.valueOf(opt.getValueAsUnit());
		else {
			byte[] payload=opt.getValueAsOpaque();
			return ((payload!=null && payload.length>0)? "0x"+ByteUtils.asHex(payload) : "empty");
		}
  }
	
	
	/** Gets a descritpion of a CoAP message code.
	  * @param code a CoAP message code
	  * @return the method name for requests, or the response code and reason for responses */
	private static String getCodeDescription(int code) {
		if (code>=1 && code<32) return CoapRequestMethod.getMethodByCode(code).toString();
		// else
		if (code>=64 && code<192) return CoapResponseCode.getResponseCode(code).toString();
		// else
		return null;
	}


	/** Gets a description of a CoAP message.
	  * @param msg a CoAP message
	  * @return a description of the CoAP message */
	/*private static String getMessageDescription(CoapMessage msg) {
		StringBuffer sb=new StringBuffer();
		sb.append(msg.isRequest()? "request:" : msg.isResponse()? "response:" : "message:");
		sb.append(msg.getTypeAsString());
		sb.append(' ').append(getCodeDescription(msg.getCode()));
		//sb.append(", MID=0x").append(Integer.toHexString(getMessageId()));
		sb.append(", MID=").append(msg.getMessageId());
		byte[] token=msg.getToken();
		sb.append(", Token=").append((token!=null? "0x"+ByteUtils.asHex(token) : null));
		byte[] payload=msg.getPayload();
		sb.append(", Payload=").append(payload!=null? payload.length : 0).append("B");
		//sb.append(", Payload=").append((payload!=null? "0x"+ByteUtils.asHex(payload) : null)).append(")");
		return sb.toString();
	}*/


	/** Gets a description of a CoAP message.
	 * @param msg a CoAP message
	 * @return a description of the CoAP message */
	private static String getMessageDescription(CoapMessage msg) {
		StringBuffer sb=new StringBuffer();
		sb.append("CoAP ");
		if (msg.isRequest()) sb.append("request: ").append(new CoapRequest(msg).toString());
		else
		if (msg.isResponse()) sb.append("response: ").append(new CoapResponse(msg).toString());
		else
			sb.append("message: ").append(msg.toString());
		return sb.toString();
	}
}
