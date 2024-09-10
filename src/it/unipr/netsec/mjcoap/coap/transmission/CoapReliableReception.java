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
package it.unipr.netsec.mjcoap.coap.transmission;

import java.net.InetSocketAddress;

import org.zoolu.util.Timer;
import org.zoolu.util.TimerListener;

import MyProject.CoapMessage;
import it.unipr.netsec.mjcoap.coap.message.CoapMessageFormatException;
import it.unipr.netsec.mjcoap.coap.message.CoapMessageType;
import it.unipr.netsec.mjcoap.coap.provider.CoapId;
import it.unipr.netsec.mjcoap.coap.provider.CoapProvider;
import it.unipr.netsec.mjcoap.coap.provider.CoapProviderListener;

/**
 * CoAP reliable reception.
 */
public class CoapReliableReception {

    /**
     * EXCHANGE_LIFETIME [millisec]
     */
    //public static long EXCHANGE_LIFETIME=(long)(CoapReliableTransmission.ACK_TIMEOUT*((1<<CoapReliableTransmission.MAX_RETRANSMIT)-1)*CoapReliableTransmission.ACK_RANDOM_FACTOR);
    public static long EXCHANGE_LIFETIME = 100000;

    /**
     * NON_LIFETIME [millisec]
     */
    public static long NON_LIFETIME = 100000;

    /**
     * CoapProvider
     */
    CoapProvider coap_provider;

    /**
     * Socket address of the remote end-point
     */
    InetSocketAddress remote_soaddr;

    /**
     * Message ID
     */
    int message_id;

    /**
     * ACK message
     */
    CoapMessage ack = null;

    /**
     * Creates a new CoapReliableReception.
     *
     * @param coap_provider the CoAP provider
     * @param con the confirmable message (that is the message that has to be
     * confirmed)
     */
    public CoapReliableReception(CoapProvider coap_provider, CoapMessage con) {
        init(coap_provider, con, null);
    }

    /**
     * Creates a new CoapReliableReception.
     *
     * @param coap_provider the CoAP provider
     * @param con the confirmable message (that is the message that has to be
     * confirmed)
     * @param ack the confirmation message (to be sent)
     */
    public CoapReliableReception(CoapProvider coap_provider, CoapMessage con, CoapMessage ack) {
        init(coap_provider, con, ack);
    }

    /**
     * Inits the CoapReliableReception.
     *
     * @param coap_provider the CoAP provider
     * @param con the confirmable message (that is the message that has to be
     * confirmed)
     * @param ack the confirmation message (to be sent), or null
     */
    private void init(CoapProvider coap_provider, CoapMessage con, CoapMessage ack) {
        this.coap_provider = coap_provider;
        message_id = con.getMessageId();
        remote_soaddr = con.getRemoteSoAddress();
        CoapProviderListener this_cp_listener = new CoapProviderListener() {
            @Override
            public void onReceivedMessage(CoapProvider coap_provider, CoapMessage msg) {
                processReceivedMessage(coap_provider, msg);
            }
        };
        coap_provider.addListener(CoapId.getReliableTransmissionId(remote_soaddr, message_id), this_cp_listener);
        if (ack == null)
		try {
            ack = new CoapMessage(CoapMessageType.ACK, CoapMessage.EMPTY, message_id);
        } catch (CoapMessageFormatException e) {
            e.printStackTrace();
        }
        this.ack = ack;
        if (ack != null) {
            coap_provider.send(ack, remote_soaddr);
        }
        TimerListener timer_listener = new TimerListener() {
            @Override
            public void onTimeout(Timer t) {
                processTimeout(t);
            }
        };
        Timer timer = new Timer(EXCHANGE_LIFETIME, timer_listener);
        timer.start();
    }

    /**
     * When a new CoAP message is received.
     *
     * @param coap_provider the CoAP provider
     * @param msg the received CoAP message
     */
    private void processReceivedMessage(CoapProvider coap_provider, CoapMessage msg) {
        if (ack != null) {
            coap_provider.send(ack, msg.getRemoteSoAddress());
        }
    }

    /**
     * When the Timer exceeds.
     *
     * @param t the timer
     */
    private void processTimeout(Timer t) {
        coap_provider.removeListener(CoapId.getReliableTransmissionId(remote_soaddr, message_id));
        coap_provider = null;
    }

}
