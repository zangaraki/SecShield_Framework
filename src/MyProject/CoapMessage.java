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
package MyProject;

import org.zoolu.util.ByteUtils;
import org.zoolu.util.Random;
import org.zoolu.util.SortedVector;

import it.unipr.netsec.mjcoap.coap.option.*;

import java.net.InetSocketAddress;
import java.util.List;
import java.util.Vector;
import MyProject.Packet;
import it.unipr.netsec.mjcoap.coap.message.CoapMessageFormatException;
import it.unipr.netsec.mjcoap.coap.message.CoapMessageType;
import it.unipr.netsec.mjcoap.coap.message.CoapRequestMethod;
import it.unipr.netsec.mjcoap.coap.message.CoapResponseCode;

/**
 * CoapMessage is a CoAP message as defined in the IETF RFC 7252 "Constrained
 * Application Protocol (CoAP)".
 * <p>
 * CoAP messages are encoded in a simple binary format. The message format
 * starts with a fixed-size 4-byte header. This is followed by a variable-length
 * Token value which can be between 0 and 8 bytes long. Following the Token
 * value comes a sequence of zero or more CoAP Options in Type-Length-Value
 * (TLV) format, optionally followed by a payload which takes up the rest of the
 * datagram.
 */
public class CoapMessage {

    /**
     * Version (Ver): 2-bit unsigned integer. Indicates the CoAP version number.
     * Implementations of this specification MUST set this field to 1. Other
     * values are reserved for future versions
     */
    static final short VER = 0x1;

    /**
     * Payload Marker (0xFF)
     */
    static final byte PAYLOAD_MARKER = (byte) 0xff;

    /**
     * Message code for empty message (0)
     */
    public static final int EMPTY = 0;

    /**
     * Default token length
     */
    public static final int DEFAULT_TOKEN_LEN = 4;

    /**
     * Type (T): 2-bit unsigned integer. Indicates if this message is of type
     * Confirmable (0), Non-Confirmable (1), Acknowledgement (2) or Reset (3)
     */
    protected CoapMessageType type;

    /**
     * Token Length (TKL): 4-bit unsigned integer. Indicates the length of the
     * variable-length Token field (0-8 bytes). Lengths 9-15 are reserved, MUST
     * NOT be sent, and MUST be processed as a message format error
     */
    //short token_length;
    /**
     * Code: 8-bit unsigned integer. Indicates if the message carries a request
     * (1-31) or a response (64-191), or is empty (0). (All other code values
     * are reserved.) In case of a request, the Code field indicates the Request
     * Method; in case of a response a Response Code
     */
    int code;

    /**
     * Message ID: 16-bit unsigned integer in network byte order. Used for the
     * detection of message duplication, and to match messages of type
     * Acknowledgement/Reset to messages of type Confirmable/ Non-confirmable
     */
    int message_id;

    /**
     * Token ("request ID"): may be 0 to 8 bytes, as given by the Token Length
     * field. The Token value is used to correlate requests and responses
     */
    byte[] token = null;
    /**
     * Options: zero or more Options. An Option can be followed by the end of
     * the message, by another Option, or by the Payload Marker and the payload
     */
    SortedVector options = new SortedVector();

    /**
     * Payload: the optional payload. If present and of non-zero length, it is
     * prefixed by a fixed, one-byte Payload Marker (0xFF) which indicates the
     * end of options and the start of the payload. The payload data extends
     * from after the marker to the end of the UDP datagram, i.e., the Payload
     * Length is calculated from the datagram size. The absence of the Payload
     * Marker denotes a zero-length payload
     */
    byte[] payload = null;
    Boolean MessageEncrypted = false;

    /**
     * Remote socket address
     */
    InetSocketAddress remote_soaddr = null;

    String Crypto_Alg = "RSA"; // RSA, RSA-AES
    boolean Encrypted;

    //========================================
    public CoapMessage() {
        super();
        setToken(CoapMessage.pickToken(CoapMessage.DEFAULT_TOKEN_LEN));
    }
    //========================================
    /**
     * Creates a new CoapMessage.
     *
     * @param msg a CoAP message
     */
    public CoapMessage(CoapMessage msg) {
        init(msg.type, msg.code, msg.message_id,
                msg.token, (Vector<CoapOption>) msg.options.toVector(),
                msg.payload);
        this.remote_soaddr = msg.remote_soaddr;
    }

    /**
     * Creates a new CoapMessage.
     *
     * @param type message type (Confirmable (0), Non-Confirmable (1),
     * Acknowledgement (2) or Reset (3))
     * @param code request method (1-31) or response code (64-191), or 0 for
     * empty message
     */
    public CoapMessage(CoapMessageType type, int code) {
        init(type, code, CoapMessage.pickMessageId(),
                null, null, null);
    }

    /**
     * Creates a new CoapMessage.
     *
     * @param type message type (Confirmable (0), Non-Confirmable (1),
     * Acknowledgement (2) or Reset (3))
     * @param code request method (1-31) or response code (64-191), or 0 for
     * empty message
     * @param message_id message ID, used for the detection of message
     * duplication, and to match messages of type Acknowledgement/Reset to
     * messages of type Confirmable/Non-confirmable
     */
    public CoapMessage(CoapMessageType type, int code, int message_id) {
        init(type, code, message_id, null, null, null);
    }

    /**
     * Creates a new CoapMessage.
     *
     * @param type message type (Confirmable (0), Non-Confirmable (1),
     * Acknowledgement (2) or Reset (3))
     * @param code request method (1-31) or response code (64-191), or 0 for
     * empty message
     * @param message_id message ID, used for the detection of message
     * duplication, and to match messages of type Acknowledgement/Reset to
     * messages of type Confirmable/Non-confirmable
     * @param token the token used to correlate requests and responses (if any)
     * @param options array of message options (if any)
     * @param payload message payload
     */
    /*public CoapMessage(CoapMessageType type, int code, int message_id, byte[] token, CoapOption[] options, byte[] payload) {
		init(type,code,message_id,token,((options!=null)?java.util.Arrays.asList(options):null),payload);
	}*/
    /**
     * Creates a new CoapMessage.
     *
     * @param type message type (Confirmable (0), Non-Confirmable (1),
     * Acknowledgement (2) or Reset (3))
     * @param code request method (1-31) or response code (64-191), or 0 for
     * empty message
     * @param message_id message ID, used for the detection of message
     * duplication, and to match messages of type Acknowledgement/Reset to
     * messages of type Confirmable/Non-confirmable
     * @param token the token used to correlate requests and responses (if any)
     * @param options list of message options (if any)
     * @param payload message payload
     */
    /*public CoapMessage(short type, int code, int message_id, byte[] token, List<CoapOption> options, byte[] payload) {
		init(type,code,message_id,token,options,payload);
	}*/
    /**
     * Creates a new CoapMessage.
     *
     * @param type message type (Confirmable (0), Non-Confirmable (1),
     * Acknowledgement (2) or Reset (3))
     * @param code request method (1-31) or response code (64-191), or 0 for
     * empty message
     * @param message_id message ID, used for the detection of message
     * duplication, and to match messages of type Acknowledgement/Reset to
     * messages of type Confirmable/Non-confirmable
     * @param token the token used to correlate requests and responses (if any)
     * @param options list of message options (if any)
     * @param payload message payload
     */
    private void init(CoapMessageType type, int code, int message_id, byte[] token, List<CoapOption> options, byte[] payload) {
        if (type == null) {
            throw new CoapMessageFormatException("invalid message type (" + type + ")");
        }
        this.type = type;
        if (!(isEmpty() || isRequest() || isResponse())) {
            throw new CoapMessageFormatException("invalid message code (" + code + ")");
        }
        this.code = code;
        if (isCON() && isEmpty()) {
            throw new CoapMessageFormatException("Confirmable message must not be empty");
        }
        this.message_id = message_id;
        if (token != null && token.length > 8) {
            throw new CoapMessageFormatException("invalid token length (" + token.length + "); it must be less than 9");
        }
        this.token = token;
        if (options != null) {
            this.options.addElements(options);
        }
        this.payload = payload;
    }

    /**
     * Creates a new CoapMessage.
     *
     * @param buf buffer containing the CoAP message
     * @param off message offset within the buffer
     * @param len message length
     */
    public CoapMessage(byte[] buf, int off, int len) {
        init(buf, off, len);
    }

    /**
     * Creates a new CoapMessage.
     *
     * @param data the CoAP message bytes
     */
    public CoapMessage(byte[] data) {
        init(data, 0, data.length);
    }

    /**
     * Initializes the CoapMessage.
     *
     * @param buf buffer containing the CoAP message
     * @param off message offset within the buffer
     * @param len message length
     */
    private void init(byte[] buf, int off, int len) {
        int index = off;
        int ver = (buf[index] >> 6) & 0x3;
        if (ver != VER) {
            throw new CoapMessageFormatException("invalid CoAP version (" + ver + ")");
        }
        // else
        this.type = CoapMessageType.getMessageTypeByCode((buf[index] >> 4) & 0x3);
        int token_len = buf[index++] & 0xf;
        this.code = buf[index++] & 0xff;
        if (isEmpty() && token_len > 0) {
            throw new CoapMessageFormatException("found token within an emply message");
        }
        // else
        this.message_id = ((buf[index] & 0xff) << 8) + (buf[index + 1] & 0xff);
        index += 2;
        if (token_len > 0) {
            this.token = new byte[token_len];
            System.arraycopy(buf, index, token, 0, token_len);
            index += token_len;
        }
        int prev_opt_num = 0;
        while (index < len && buf[index] != PAYLOAD_MARKER) {
            CoapOption opt = CoapOption.parseCoapOption(prev_opt_num, buf, index);
            options.addElement(opt);
            //addSortedElement(options,opt);
            index += opt.getLength(prev_opt_num);
            prev_opt_num = opt.getOptionNumber();
        }
        if (index < len) {
            index++;
            if (index == len) {
                throw new CoapMessageFormatException("payload marker without a payload");
            }
            // else
            int payload_len = off + len - index;
            this.payload = new byte[payload_len];
            System.arraycopy(buf, index, this.payload, 0, payload_len);
        }
    }

    /**
     * Sets the remote socket address.
     *
     * @param remote_soaddr the socket address
     */
    public void setRemoteSoAddress(InetSocketAddress remote_soaddr) {
        this.remote_soaddr = remote_soaddr;
    }

    /**
     * Gets the remote socket address.
     *
     * @return the remote socket address
     */
    public InetSocketAddress getRemoteSoAddress() {
        return remote_soaddr;
    }

    /**
     * Sets the message type.
     *
     * @param type message type (Confirmable (0), Non-Confirmable (1),
     * Acknowledgement (2) or Reset (3))
     * @return this message
     */
    public CoapMessage setType(CoapMessageType type) {
        if (type == null) {
            throw new CoapMessageFormatException("invalid message type (" + type + ")");
        }
        this.type = type;
        return this;
    }

    /**
     * Gets the message type. Type indicates if this message is of type
     * Confirmable (0), Non-Confirmable (1), Acknowledgement (2) or Reset (3).
     *
     * @return the message type
     */
    public CoapMessageType getType() {
        return type;
    }

    /**
     * Whether message is Confirmable (0).
     *
     * @return true if Confirmable (0), false otherwise
     */
    public boolean isCON() {
        return type.equals(CoapMessageType.CON);
    }

    /**
     * Whether message is Non-Confirmable (1).
     *
     * @return true if Non-Confirmable (1), false otherwise
     */
    public boolean isNON() {
        return type.equals(CoapMessageType.NON);
    }

    /**
     * Whether message is Acknowledgement (2).
     *
     * @return true if Acknowledgement (2), false otherwise
     */
    public boolean isACK() {
        return type.equals(CoapMessageType.ACK);
    }

    /**
     * Whether message is Reset (3).
     *
     * @return true if Reset (3), false otherwise
     */
    public boolean isRST() {
        return type.equals(CoapMessageType.RST);
    }

    /**
     * Sets message code.
     *
     * @param code the message code, indicating the request method (1-31) for
     * requests, the response code (64-191) for responses, or is empty (0)
     * @return this message
     */
    public CoapMessage setCode(int code) {
        if (!(isEmpty() || isRequest() || isResponse())) {
            throw new CoapMessageFormatException("invalid message code (" + code + ")");
        }
        //if (isCON() && isEmpty()) throw new CoapMessageFormatException("Confirmable message must not be empty");
        this.code = code;
        return this;
    }

    /**
     * Gets message code. Code indicates if the message carries a request (1-31)
     * or a response (64-191), or is empty (0) (All other code values are
     * reserved). In case of a request, the Code field indicates the Request
     * Method; in case of a response a Response Code.
     *
     * @return the message code
     */
    public int getCode() {
        return code;
    }

    /**
     * Gets message code as string.
     *
     * @return "empty" for empty message, "GET" for GET request, "POST" for POST
     * request, "PUT" for PUT request, "DELETE" for DELETE request, or response
     * code descrition for responses
     */
    public String getCodeAsString() {
        return getCodeAsString(code);
    }

    /**
     * Gets a string representation of a message code.
     *
     * @param code the message code
     * @return "empty" for empty message, "GET" for GET request, "POST" for POST
     * request, "PUT" for PUT request, "DELETE" for DELETE request, or response
     * code descrition for responses
     */
    public static String getCodeAsString(int code) {
        // empty
        if (code == EMPTY) {
            return "empty";
        }
        // else
        // request
        //if (code>=1 && code<32) return String.valueOf(code);
        if (isRequestCode(code)){ 
            Config.Action="GET";
            return CoapRequestMethod.getMethodByCode(code).toString();
        }
        // else
        // response
        //if (code>=64 && code<192) return String.valueOf((code>>5)&0x7)+"."+String.valueOf(code&0x1f);
        if (isResponseCode(code)) {
            Config.Action="PUT";
            return CoapResponseCode.getResponseCode(code).toString();
        }
        // else
        // request
        return String.valueOf(code);
    }

    /**
     * Whether message is a request (code 1-31).
     *
     * @return true if it is a request, false otherwise
     */
    public boolean isRequest() {
        return isRequestCode(code);
    }

    /**
     * Whether message is a response (code 64-191).
     *
     * @return true it is a response, false otherwise
     */
    public boolean isResponse() {
        return isResponseCode(code);
    }

    /**
     * Whether message is a request (code 1-31).
     *
     * @param message code
     * @return true if it is a request, false otherwise
     */
    private static boolean isRequestCode(int code) {
        return code >= 1 && code < 32;
    }

    /**
     * Whether message is a response (code 64-191).
     *
     * @param message code
     * @return true it is a response, false otherwise
     */
    private static boolean isResponseCode(int code) {
        return code >= 64 && code < 192;
    }

    /**
     * Whether message is empty, that is it contains neither a request nor a
     * response.
     *
     * @return true if it is empty, false otherwise
     */
    public boolean isEmpty() {
        return code == EMPTY;
    }

    /**
     * Sets the message ID.
     *
     * @param message_id the message ID
     * @return this message
     */
    public CoapMessage setMessageId(int message_id) {
        this.message_id = message_id;
        return this;
    }

    /**
     * Gets message ID. Message ID is used for the detection of message
     * duplication, and to match messages of type Acknowledgement/Reset to
     * messages of type Confirmable/Non-confirmable
     *
     * @return the message ID
     */
    public int getMessageId() {
        return message_id;
    }

    /**
     * Sets message token ("request ID").
     *
     * @param token the message token (or null)
     * @return this message
     */
    public CoapMessage setToken(byte[] token) {
        if (token != null && token.length > 8) {
            throw new CoapMessageFormatException("invalid token length (" + token.length + "); it must be less than 9");
        }
        this.token = token;
        return this;
    }

    /**
     * Gets message token ("request ID"). The Token value is used to correlate
     * requests and responses. It may be 0 (null) to 8 bytes.
     *
     * @return the token (or null in case no token is present)
     */
    public byte[] getToken() {
        return token;
    }

    /**
     * Gets message token ("request ID") as hexadecimal string. The Token value
     * is used to correlate requests and responses. It may be 0 (null) to 8
     * bytes.
     *
     * @return the hexadecimal representation of the token (or null in case no
     * token is present)
     */
    public String getTokenAsString() {
        return getTokenAsString(token);
    }

    /**
     * Gets a hexadecimal representation of a message token ("request ID"). The
     * Token value is used to correlate requests and responses. It may be 0
     * (null) to 8 bytes.
     *
     * @param token the message token
     * @return the hexadecimal representation of the token (or null in case no
     * token is present)
     */
    public String getTokenAsString(byte[] token) {
        if (token != null) {
            return ByteUtils.asHex(token);
        } else {
            return null;
        }
    }

    /**
     * Sets message options.
     *
     * @param options array of message options
     * @return this message
     */
    public synchronized CoapMessage setOptions(CoapOption[] options) {
        this.options.clear();
        if (options != null) {
            this.options.addElements(options);
        }
        return this;
    }

    /**
     * Sets message options.
     *
     * @param options list of message options
     * @return this message
     */
    public synchronized CoapMessage setOptions(List<CoapOption> options) {
        this.options.clear();
        if (options != null) {
            this.options.addElements(options);
        }
        return this;
    }

    /**
     * Sets a given option. If the option is already present, all occurrences
     * are first removed.
     *
     * @param opt the CoAP option to be added
     * @return this message
     */
    public synchronized CoapMessage setOption(CoapOption opt) {
        removeOption(opt.getOptionNumber());
        addOption(opt);
        return this;
    }

    /**
     * Removes all occurrences of a given option number.
     *
     * @param opt_number the option number to be removed
     * @return this message
     */
    public synchronized CoapMessage removeOption(int opt_number) {
        for (int i = 0; i < options.size(); i++) {
            CoapOption opt_i = (CoapOption) options.elementAt(i);
            int comparison = opt_i.getOptionNumber() - opt_number;
            if (comparison == 0) {
                options.removeElementAt(i--);
            } else if (comparison > 0) {
                break;
            }
        }
        return this;
    }

    /**
     * Gets all message options.
     *
     * @return an array of all message options
     */
    public synchronized CoapOption[] getOptions() {
        //return (CoapOption[])options.toArray();
        return (CoapOption[]) options.toArray(new CoapOption[options.size()]);
    }

    /**
     * Whether there is a given number.
     *
     * @param opt_num the option number
     * @return <i>true</i> if the option is present
     */
    public synchronized boolean hasOption(int opt_num) {
        for (int i = 0; i < options.size(); i++) {
            CoapOption opt = (CoapOption) options.elementAt(i);
            if (opt.getOptionNumber() == opt_num) {
                return true;
            }
            // else
            if (opt.getOptionNumber() > opt_num) {
                break;
            }
        }
        return false;
    }

    /**
     * Gets message option with a given number.
     *
     * @param opt_num the option number
     * @return the first option with the given option number, if preset, or
     * <i>null</i>
     */
    public synchronized CoapOption getOption(int opt_num) {
        for (int i = 0; i < options.size(); i++) {
            CoapOption opt = (CoapOption) options.elementAt(i);
            if (opt.getOptionNumber() == opt_num) {
                return opt;
            }
            // else
            if (opt.getOptionNumber() > opt_num) {
                break;
            }
        }
        return null;
    }

    /**
     * Gets all message options with a given number.
     *
     * @param opt_num the option number
     * @return the options with the given option number, if any, or <i>null</i>
     */
    public synchronized CoapOption[] getOptions(int opt_num) {
        Vector<CoapOption> temp = new Vector<CoapOption>();
        for (int i = 0; i < options.size(); i++) {
            CoapOption opt = (CoapOption) options.elementAt(i);
            if (opt.getOptionNumber() == opt_num) {
                temp.addElement(opt);
            }
            // else
            if (opt.getOptionNumber() > opt_num) {
                break;
            }
        }
        if (temp.size() >= 0) {
            return (CoapOption[]) temp.toArray(new CoapOption[temp.size()]);
        }
        // else
        return null;
    }

    /**
     * Adds an option.
     *
     * @param opt the CoAP option to be added
     * @return this message
     */
    public synchronized CoapMessage addOption(CoapOption opt) {
        options.addElement(opt);
        return this;
    }

    /**
     * Sets message payload.
     *
     * @param payload the message payload (or null)
     * @return this message
     */
    public synchronized CoapMessage setPayload(byte[] payload) {
        this.payload = payload;
        return this;
    }

    /**
     * Gets message payload.
     *
     * @return the message payload (or null in case no payload is present)
     */
    public byte[] getPayload() {

        if (payload == null || payload.length == 0) {
            return null;
        } else {
            return payload;
        }
    }

    /**
     * Gets bytes of this CoAP message.
     *
     * @return the raw bytes of this CoAP message
     */
    public synchronized byte[] getBytes() {
        int token_len = (token != null) ? token.length : 0;
        int options_len = getOptionsLength();
        int len = 4 + token_len + options_len;
        if (payload != null && payload.length > 0) {
            len += 1 + payload.length;
        }
        byte[] data = new byte[len];
        getBytes(data, 0);
        return data;
    }

    /**
     * Gets bytes of this CoAP message.
     *
     * @param buf the buffer where the bytes will be written
     * @param off an offset within the given buffer
     * @return the number of bytes that have been written (that is also the
     * total length of the CoAP message)
     */
    public synchronized int getBytes(byte[] buf, int off) {
        int token_len = (token != null) ? token.length : 0;
        int index = off;
        short type_code = type.getCode();
        buf[index++] = (byte) (((VER & 0x3) << 6) | ((type_code & 0x3) << 4) | (token_len & 0xf));
        buf[index++] = (byte) (code & 0xff);
        buf[index++] = (byte) ((message_id >> 8) & 0xff);
        buf[index++] = (byte) (message_id & 0xff);
        if (token != null) {
            for (int i = 0; i < token_len; i++) {
                buf[index++] = token[i];
            }
        }
        if (options != null) {
            int prev_opt_num = 0;
            for (int i = 0; i < options.size(); i++) {
                CoapOption opt = (CoapOption) options.elementAt(i);
                index += opt.getBytes(prev_opt_num, buf, index);
                prev_opt_num = opt.getOptionNumber();
            }
        }
        if (payload != null && payload.length > 0) {
            buf[index++] = PAYLOAD_MARKER;
            for (int i = 0; i < payload.length; i++) {
                buf[index++] = payload[i];
            }
        }
        return index - off;
    }

    /**
     * Gets the total length of the options.
     *
     * @return total length of the options
     */
    private synchronized int getOptionsLength() {
        int len = 0;
        if (options != null) {
            int prev_opt_num = 0;
            for (int i = 0; i < options.size(); i++) {
                CoapOption opt = (CoapOption) options.elementAt(i);
                len += opt.getLength(prev_opt_num);
                prev_opt_num = opt.getOptionNumber();
            }
        }
        return len;
    }

    /**
     * Gets a string representation of this object.
     *
     * @return a summary of this CoAP message
     */
    @Override
    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append(type.toString());
        sb.append(",").append(getCodeAsString());
        //sb.append(",").append(Integer.toHexString(getMessageId()));
        sb.append(",MID=").append(getMessageId());
        byte[] token = getToken();
        sb.append(",Token=").append(((token != null) ? "0x" + ByteUtils.asHex(token) : null));
        sb.append(",Payload=").append(getPayloadAsString());
        return sb.toString();
    }

    /**
     * Gets a string representation of the message options.
     *
     * @return a string of all message options
     */
    protected synchronized String getOptionsAsString() {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < options.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(CoapOptionNumber.getOptionName(((CoapOption) options.elementAt(i)).getOptionNumber()));
        }
        return sb.toString();
    }

    /**
     * Gets a string representation of the payload.
     *
     * @return a string of all message options
     */
    protected synchronized String getPayloadAsString() {
        //return payload!=null? "0x"+ByteUtils.asHex(payload) : null;
        if (payload == null) {
            return null;
        }
        // else
        for (int i = 0; i < payload.length; i++) {
            if (payload[i] < 32 || payload[i] > 127) {
                return "0x" + ByteUtils.asHex(payload);
            }
        }
        return ByteUtils.asAscii(payload);
    }

    /**
     * Counter used to sequentially generate message IDs
     */
    //private static int MESSAGE_ID_COUNTER=0;
    private static int MESSAGE_ID_COUNTER = Random.nextInt() & 0x0fff;

    /**
     * Picks a fresh message ID.
     *
     * @return the new message ID
     */
    public static int pickMessageId() {
        return (MESSAGE_ID_COUNTER++) & 0xffff;
        //return Random.nextInt()&0xffff;
    }

    /**
     * Picks a fresh token.
     *
     * @return the new token
     */
    public static byte[] pickToken() {
        return pickToken(DEFAULT_TOKEN_LEN);
    }

    /**
     * Picks a fresh token.
     *
     * @param len the token length
     * @return the new token
     */
    public static byte[] pickToken(int len) {
        if (len <= 0) {
            return null;
        }
        // else
        return Random.nextBytes(len);
    }

    // METHODS FOR GETTING AND SETTING OPTIONS THAT APPLY TO BOTH REQUESTS AND RESPONSES
    /**
     * Sets content format.
     *
     * @param format content format identifier
     */
    public void setContentFormat(int format) {
        setOption(new ContentFormatOption(format));
    }

    /**
     * Gets content format.
     *
     * @return content format identifier
     */
    public int getContentFormat() {
        CoapOption cf_opt = getOption(CoapOptionNumber.ContentFormat);
        if (cf_opt != null) {
            return new ContentFormatOption(cf_opt).getContentFormatIdentifier();
        } else {
            return -1;
        }
    }

    /**
     * Sets payload with a given content format.
     *
     * @param format content format identifier (or -1)
     * @param payload the payload
     */
    public void setPayload(int format, byte[] payload) {
        if (format >= 0) {
            setContentFormat(format);
        }
        setPayload(payload);
    }

    public Boolean ISMessageEncrypted() {
        return MessageEncrypted;
    }

    public void SetMessageEncryption() {
        MessageEncrypted = true;
    }

    public void setCoapMessage(boolean Encryption, String Method) {
        Encrypted = Encryption;
        Crypto_Alg = Method;
    }
}
