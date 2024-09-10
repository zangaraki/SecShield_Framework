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
package it.unipr.netsec.mjcoap.coap.transaction;


import org.zoolu.util.*;

import MyProject.CoapMessage;
import MyProject.Config;
import MyProject.NetworkOperatingSystem;
import it.unipr.netsec.mjcoap.coap.message.CoapMessageType;
import it.unipr.netsec.mjcoap.coap.message.CoapRequest;
import it.unipr.netsec.mjcoap.coap.message.CoapResponse;
import it.unipr.netsec.mjcoap.coap.provider.CoapProvider;
import it.unipr.netsec.mjcoap.coap.transmission.CoapReliableReception;
import it.unipr.netsec.mjcoap.coap.transmission.CoapReliableTransmission;
import it.unipr.netsec.mjcoap.coap.transmission.CoapReliableTransmissionListener;
import java.util.logging.Level;

/**
 * CoAP transaction server. It handles a server-side CoAP transaction.
 * <p>
 * A transaction server is created by specifying:
 * <ul>
 * <li>the CoAP provider, used to receive possible request retransmissions and
 * to send the response,</li>
 * <li>the request message,</li>
 * <li>the transaction server listener.</li>
 * </ul>
 * The response message can be sent by the server by calling the method
 * {@link #respond(CoapResponse)}.
 * <p>
 * The transaction server automatically handles the reception of possible
 * (multiple copies of) the request, by: i) sending the ACK message in case of
 * CON requests, ii) re-sending the given response, if the method
 * {@link #respond(CoapResponse)} has been already called.
 */
public class CoapTransactionServer {

    /**
     * Logs a warning message.
     *
     * @param str the message to be logged
     */
    private void warning(String str) {
        SystemUtils.log(LoggerLevel.WARNING, getClass(), str);
    }

    /**
     * waiting time for piggybacked responses (in milliseconds)
     */
    public static long PIGGYBACKED_TIME = 200;

    /**
     * CoapProvider
     */
    CoapProvider coap_provider;

    /**
     * CoapTransactionServer listener
     */
    CoapTransactionServerListener ts_listener;

    /**
     * Remote socket address
     */
    //SocketAddress remote_soaddr;
    /**
     * Whether request is confirmable
     */
    //boolean confirmable;
    /**
     * Request
     */
    CoapRequest req;

    /**
     * Response
     */
    CoapResponse resp = null;

    /**
     * Piggybacked timer
     */
    Timer piggybacked_timer = null;

    /**
     * Whether the response has been sent
     */
    //boolean response_sent=false;
    /**
     * Creates a new CoapTransactionServer.
     *
     * @param coap_provider the CoAP provider
     * @param req the request message
     * @param ts_listener transaction server listener
     */
    public CoapTransactionServer(CoapProvider coap_provider, CoapRequest req,
            CoapTransactionServerListener ts_listener) {
        this.coap_provider = coap_provider;
        this.req = req;
      
        this.ts_listener = ts_listener;
        if (req.isCON()) {
            if (PIGGYBACKED_TIME > 0) {
                TimerListener t_listener = new TimerListener() {
                    public void onTimeout(Timer t) {
                        processPiggyBackedTimeout();
                    }
                };
                piggybacked_timer = new Timer(PIGGYBACKED_TIME, t_listener);
                piggybacked_timer.start();
            } else {
                new CoapReliableReception(coap_provider, req);
            }
        }
    }

    /**
     * Gets the request message.
     *
     * @return the request message
     */
    public CoapRequest getRequestMessage() {
        return req;
    }

    /**
     * When piggybacked timeout expires.
     */
    private void processPiggyBackedTimeout() {
        printLog("processPiggyBackedTiemout()");
        // send ACK
        new CoapReliableReception(coap_provider, req);
    }

    /**
     * Sends CoAP response.
     *
     * @param response_code the response code
     * @param payload the payload, if any, or null
     */
    /*public synchronized void respond(int response_code, byte[] payload) {
		if (this.resp!=null) {
			warning("respond(): response message already sent");
			return;
		}
		// else
		CoapResponse resp=CoapMessageFactory.createResponse(req,response_code,payload);
		respond(resp);
	}*/
    /**
     * Sends CoAP response.
     *
     * @param resp the response message
     */
    public synchronized void respond(CoapResponse resp) {
        if (this.resp != null) {
            warning("respond(): response message already sent");
            return;
        }
        // else
        this.resp = resp;
        //Config.CoapServers.get(resp.get)
//        if (Config.Cryptography.endsWith("RSA")) {
//                try {
//                    byte[] cipherText = do_RSAEncryption(resp.getPayload(),
//                            keypair_RSA.getPrivate());
////                    server.setCoapMessage(true, "RSA");
//                } catch (Exception ex) {
//                    java.util.logging.Logger.getLogger(NetworkOperatingSystem.class.getName()).log(Level.SEVERE, null, ex);
//                }
//            } else if (Config.Cryptography.endsWith("RSA-AES")) {
//                try {
//                    // Encrypt our data with AES key
//                    String encryptedText = encryptTextUsingAES(resp.getPayload(),
//                            secretAESKeyString);
//
//                    // Encrypt AES Key with RSA Private Key
//                    encryptedAESKeyString
//                            = encryptAESKey(secretAESKeyString,
//                                    privateKey_RSA_AES);
//                    server.setCoapMessage(true, "RSA-AES");
//
//                } catch (Exception ex) {
//                    java.util.logging.Logger.getLogger(NetworkOperatingSystem.class.getName()).log(Level.SEVERE, null, ex);
//                }
//            }
//        
        
        resp.setToken(req.getToken());
        // try to send piggybacked response
        if (piggybacked_timer != null && piggybacked_timer.isRunning()) {
            // the request is CON and is still waiting for a response: send the response as an ACK (or RST) (piggybacked)
            piggybacked_timer.halt();
            if (!resp.isRST()) {
                resp.setType(CoapMessageType.ACK);
            }
            resp.setMessageId(req.getMessageId());
            new CoapReliableReception(coap_provider, req, resp);
        } else // if you want to convert possible ACK responses to CON responses, do it here
        //..
        if (resp.isCON() || resp.isNON()) {
            // if you want to have always CON responses for CON requests, do it here
            //..
            if (resp.isCON()) {
                // resp=CON,Response
                CoapReliableTransmissionListener rt_listener = new CoapReliableTransmissionListener() {
                    public void onTransmissionAcknowledgement(CoapReliableTransmission reliable_transmission, CoapMessage ack) {
                        processTransmissionAcknowledgement(reliable_transmission, ack);
                    }

                    public void onTransmissionReject(CoapReliableTransmission reliable_transmission, CoapMessage rst) {
                        processTransmissionReject(reliable_transmission, rst);
                    }

                    public void onTransmissionTimeout(CoapReliableTransmission reliable_transmission) {
                        processTransmissionTimeout(reliable_transmission);
                    }
                };
                new CoapReliableTransmission(coap_provider, req.getRemoteSoAddress(), rt_listener).send(resp);
            } else if (resp.isNON()) {
                // resp=NON,Response
                coap_provider.send(resp, req.getRemoteSoAddress());
            } else {
                // what doing with ACK or RST responses here?
                // TODO
            }
        }
    }

    /**
     * When a new CoAP message is received.
     */
    /*private void processReceivedMessage(CoapProvider coap_provider, CoapMessage msg) {
		
	}*/
    /**
     * When ACK is received confirming a reliable transmission.
     */
    private void processTransmissionAcknowledgement(CoapReliableTransmission reliable_transmission, CoapMessage ack) {
        // do something?
    }

    /**
     * When RST is received confirming a reliable transmission.
     */
    private void processTransmissionReject(CoapReliableTransmission reliable_transmission, CoapMessage rst) {
        if (ts_listener != null) {
            ts_listener.onTransactionFailure(this);
        }
    }

    /**
     * When maximum retransmission has been reached without receiving any ACK
     * (or RST).
     */
    private void processTransmissionTimeout(CoapReliableTransmission reliable_transmission) {
        if (ts_listener != null) {
            ts_listener.onTransactionFailure(this);
        }
    }

    /**
     * Prints a log message.
     */
    public void printLog(String str) {
        Logger logger = SystemUtils.getDefaultLogger();
        if (logger != null) {
            logger.log(LoggerLevel.INFO, getClass(), str);
        }
    }

}
