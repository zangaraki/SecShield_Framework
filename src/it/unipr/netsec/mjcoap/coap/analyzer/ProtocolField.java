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

package it.unipr.netsec.mjcoap.coap.analyzer;


import java.util.Vector;


/** Generic protocol field.
  */
public class ProtocolField {
	
	/** Tab string used for the sub-field indentation */
	public static String TAB="   ";

	/** Field description */
	String field;

	/** Sub-fields */
	//Vector<ProtocolField> sub_fields;
	Vector sub_fields;



	/** Creates a new ProtocolField.
	  * @param field field description */
	public ProtocolField(String field) {
		this.field=field;
		this.sub_fields=null;
	}

	/** Creates a new ProtocolField.
	  * @param field field description
	  * @param sub_fields Sub-fields */
	//public ProtocolField(String field, Vector<ProtocolField> sub_fields)
	public ProtocolField(String field, Vector sub_fields) {
		this.field=field;
		this.sub_fields=sub_fields;
	}

	/** Adds a sub-field.
	  * @param sub_field Sub-field to be added */
	public void addSubField(ProtocolField sub_field) {
		//if (sub_fields==null) sub_fields=new Vector<ProtocolField>();
		if (sub_fields==null) sub_fields=new Vector();
		sub_fields.addElement(sub_field);
	}

	/** Adds a sub-field.
	  * @param str description of the field to be added */
	public void addSubField(String str) {
		addSubField(new ProtocolField(str));
	}

	/** Gets field description. */
	public String getField() {
		return field;
	}

	/** Whether has sub-fields. */
	public boolean hasSubFields() {
		return (sub_fields!=null && sub_fields.size()>0);
	}

	/** Gets sub-fields. */
	//public Vector<ProtocolField> getSubFields() {
	public Vector getSubFields() {
		//if (sub_fields==null) sub_fields=new Vector<ProtocolField>();
		if (sub_fields==null) sub_fields=new Vector();
		return sub_fields;
	}  
	
	/** Gets a string representation of this object.
	  * @return a string with the description of the field and all sub-fields, indented in separate lines */
	@Override
	public String toString() {
		//return toTabString("");
		return toTabString(0,-1);
	}

	/** Gets a string representation of this object.
	  * @param max_level maximum level of intentation (-1 for infinite indentation)
	  * @return a string with the description of the field and all sub-fields, indented in separate lines */
	public String toString(int max_level) {
		return toTabString(0,max_level);
	}

	/** Gets a string representation of this object.
	  * @param tab indentation added to all lines
	  * @return a string with the description of the field and all sub-fields, indented in separate lines */
	/*private String toTabString(String tab) {
		StringBuffer sb=new StringBuffer();
		sb.append(tab+field).append('\n');
		if (sub_fields!=null)
		for (int i=0; i<sub_fields.size(); i++) {
			//sb.append(sub_fields.elementAt(i).toTabString(tab+"   "));
			sb.append(((ProtocolField)sub_fields.elementAt(i)).toTabString(tab+"   "));
		}
		return sb.toString();
	}*/

	/** Gets a string representation of this object.
	  * @param level current level of intentation
	  * @param max_level maximum level of intentation (-1 for infinite indentation)
	  * @return a string with the description of the field and all sub-fields, indented in separate lines */
	private String toTabString(int level, int max_level) {
		StringBuffer sb=new StringBuffer();
		for (int i=0; i<level; i++) sb.append(TAB);
		//sb.append(field).append('\n');
		sb.append(field);
		if (sub_fields!=null && (max_level<0 || level<max_level)) {
			level++;
			//for (int i=0; i<sub_fields.size(); i++) sb.append(sub_fields.elementAt(i).toTabString(level,max_level));
			for (int i=0; i<sub_fields.size(); i++) sb.append('\n').append(((ProtocolField)sub_fields.elementAt(i)).toTabString(level,max_level));
		}
		return sb.toString();
	}

}
