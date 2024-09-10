/*
 * Copyright (c) 2018 Luca Veltri, University of Parma
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
 */

package org.zoolu.util;




/** A generic identifier that has an unique string representation.
  */
public class Identifier {
	
	/** String value of the identifier */   
	protected String id;



	/** Creates a void Identifier. */
	protected Identifier() {
		
	}

	/** Creates a new Identifier.
	  * @param id string value of the identifier */
	public Identifier(String id) {
		this.id=id;
	}

	/** Creates a new Identifier.
	  * @param i an identifier */
	public Identifier(Identifier i) {
		this.id=i.id;
	}



	/** Whether this object equals to an other object.
	  * @param obj the other object that is compared to
	  * @return true if the two objects are equal */
	public boolean equals(Object obj) {
		try {
			Identifier i=(Identifier)obj;
			return id.equals(i.id);
		}
		catch (Exception e) {  return false;  }
	}

	/** Gets an int hash-code for this object.
	  * @return the hash-code */
	public int hashCode() {
		return id.hashCode();
	}

	/** Gets a string value for this object.
	  * @return the string */
	public String toString() {
		return id;
	}
}
