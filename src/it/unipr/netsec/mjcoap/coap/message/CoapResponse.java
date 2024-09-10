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


import MyProject.CoapMessage;
import it.unipr.netsec.mjcoap.coap.option.*;


/** CoAP response message, with method for handling CoAP-specific options.
 */
public class CoapResponse extends CoapMessage {
	

	/** Creates a new CoapResponse.
	 * @param msg a CoAP message to be copied */
	public CoapResponse(CoapMessage msg) {
		super(msg);
	}


	/** Creates a new CoapResponse.
	 * @param type message type (Confirmable (0), Non-Confirmable (1), Acknowledgement (2) or Reset (3))
	 * @param response_code response code
	 * @param message_id message ID, used for the detection of message duplication, and to match messages of type Acknowledgement/Reset to messages of type Confirmable/Non-confirmable */
	public CoapResponse(CoapMessageType type, CoapResponseCode response_code, int message_id) {
		super(type,response_code.getCode(),message_id);
	}


	/** Creates a new CoapResponse.
	 * @param type message type (Confirmable (0), Non-Confirmable (1), Acknowledgement (2) or Reset (3))
	 * @param response_code response code
	 * @param message_id message ID, used for the detection of message duplication, and to match messages of type Acknowledgement/Reset to messages of type Confirmable/Non-confirmable
	 * @param token the token used to correlate requests and responses (if any)
	 * @param options array of message options (if any)
	 * @param payload message payload */
	/*public CoapResponse(CoapMessageType type, CoapResponseCode response_code, int message_id, byte[] token, CoapOption[] options, byte[] payload) {
		super(type,response_code.getCode(),message_id,token,options,payload);
	}*/


	/** Creates a new CoapResponse.
	 * @param type message type (Confirmable (0), Non-Confirmable (1), Acknowledgement (2) or Reset (3))
	 * @param response_code response code
	 * @param message_id message ID, used for the detection of message duplication, and to match messages of type Acknowledgement/Reset to messages of type Confirmable/Non-confirmable
	 * @param token the token used to correlate requests and responses (if any)
	 * @param options list of message options (if any)
	 * @param payload message payload */
	/*public CoapResponse(CoapMessageType type, CoapResponseCode response_code, int message_id, byte[] token, List<CoapOption> options, byte[] payload) {
		super(type,response_code.getCode(),message_id,token,options,payload);
	}*/

  
	/** Gets message code as string.
	 * @return the response code (code class and code detail separated by a dot) and description (e.g. "2.01 Created") */
	@Override
	public String getCodeAsString() {
		return getResponseCode().toString();
	}


	/** Gets response code.
	 * @return the CoAP response code */
	public CoapResponseCode getResponseCode() {
		return CoapResponseCode.getResponseCode(getCode());
	}


	// METHODS FOR GETTING AND SETTING OPTIONS THAT APPLY ONLY TO RESPONSES

	/** Sets the location options (Location-Path and Location-Query options).
	  * @param location resource location
	  * @return this message */
	public CoapResponse setLocation(String location) {
		String[] location_components=location.split("\\x3f"); // i.e. "?"
		String path=null;
		String query=null;
		if (location_components.length==2) {
			path=location_components[0];
			query=location_components[1];
		}
		else
		if (location_components.length==1) {
			if (location_components[0].startsWith("/")) path=location_components[0];
			else query=location_components[0];
		}
		return setLocation(path,query);
	}

	
	/** Sets the location options (Location-Path and Location-Query options).
	 * @param path the path part of the location
	 * @param query the query part of the location
	 * @return this message */
  public CoapResponse setLocation(String path, String query)
  {  if (path!=null && path.length()>0)
	  {  String[] path_components=path.substring(1).split("/");
		  for (int i=0; path_components!=null && i<path_components.length; i++)
		  {  addOption(new CoapOption(CoapOptionNumber.LocationPath,path_components[i]));
		  }
	  }
	  if (query!=null && query.length()>0)
	  {  String[] query_components=query.split("&");
		  for (int i=0; query_components!=null && i<query_components.length; i++)
		  {  addOption(new CoapOption(CoapOptionNumber.LocationQuery,query_components[i]));
		  }
	  }
	  return this;
	}

  
	/** Gets the location of the resource (from Location-Path and Location-Query options).
	  * @return the location */
	public String getLocation() {
		StringBuffer sb=new StringBuffer();
		// path
		CoapOption[] path_opt=getOptions(CoapOptionNumber.LocationPath);
		if (path_opt!=null) {
			for (int i=0; i<path_opt.length; i++) sb.append('/').append(path_opt[i].getValueAsString());
		}
		// query
		CoapOption[] query_opt=getOptions(CoapOptionNumber.LocationQuery);
		if (query_opt!=null && query_opt.length>0) {
			sb.append('?').append(query_opt[0]);
			for (int i=1; i<query_opt.length; i++) sb.append('&').append(query_opt[i].getValueAsString());
		}
		if (sb.length()>0) return sb.toString();
		// else
		return null;
	}

	
	/** Gets the location path of the resource (from Location-Path option).
	 * @return the location path */
	public String getLocationPath() {
		CoapOption[] path_opt=getOptions(CoapOptionNumber.LocationPath);
		if (path_opt!=null) {
			StringBuffer sb=new StringBuffer();
			for (int i=0; i<path_opt.length; i++) sb.append('/').append(path_opt[i].getValueAsString());
			return sb.toString();
		}
		return null;
	}

	
	/** Sets the maximum time a response may be cached before it is considered not fresh (Max-Age option).
	 * @param max_age the maximum time in seconds
	 * @return this message */
	public CoapResponse setMaxAge(int max_age) {
		if (max_age>=0) setOption(new MaxAgeOption(max_age));
		return this;
	}


	/** Gets the maximum time a response may be cached before it is considered not fresh (from Accept option).
	 * @return the maximum time in seconds */
	public long getMaxAge() {
		CoapOption opt=getOption(CoapOptionNumber.MaxAge);
		if (opt!=null) return opt.getValueAsUnit();
		else return -1;
	}

	
	/** Sets the entity-tag (ETag option).
	 * @param entity_tag entity-tag
	 * @return this message */
	public CoapMessage setEntityTag(byte[] entity_tag) {
		if (entity_tag!=null) setOption(new ETagOption(entity_tag));
		return this;
	}


	/** Gets the entity-tag (from ETag option).
	 * @return the entity-tag */
	public byte[] getEntityTag() {
		CoapOption opt=getOption(CoapOptionNumber.ETag);
		if (opt!=null) return opt.getValueAsOpaque();
		else return null;
	}


	/** Sets observe sequence number.
	 * @param seqn the sequence number
	 * @return this message */
	public CoapResponse setObserveSequenceNumber(int seqn) {
		setOption(new ObserveOption(seqn));
		return this;
	}

	/** Gets observe sequence number.
	 * @return the sequence number or -1 (if not present) */
	public int getObserveSequenceNumber() {
		if (hasOption(CoapOptionNumber.Observe)) {
			ObserveOption oo=new ObserveOption(getOption(CoapOptionNumber.Observe));
			return oo.getSequenceNumber();
		}
		else return -1;
	}


}

