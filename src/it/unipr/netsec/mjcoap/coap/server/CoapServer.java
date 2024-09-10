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
package it.unipr.netsec.mjcoap.coap.server;

import org.zoolu.util.ByteUtils;
import org.zoolu.util.LoggerLevel;
import org.zoolu.util.Logger;
import org.zoolu.util.Random;
import org.zoolu.util.SystemUtils;

import it.unipr.netsec.mjcoap.coap.message.*;

import java.net.SocketException;
import java.util.Hashtable;
import java.util.Iterator;

/**
 * Ready-to-use simple stateful CoAP server. It handles CoAP GET, PUT, and
 * DELETE requests statefully, automatically handling request/response
 * retransmissions.
 * <p>
 * It supports resource observation (RFC 7641) and blockwise transfer (RFC
 * 7959).
 * <p>
 * Support of CoAP method POST can be easily added by extending this class and
 * overriding the method {@link #handlePostRequest(CoapRequest)} by adding the
 * proper handling of POST requests.
 * <p>
 * Local resources can be retrieved by remote clients by means of the CoAP GET
 * method.
 * <p>
 * If the server is in 'write-enabled' mode, resources can be also created,
 * changed, and removed by remote clients by means of the CoAP PUT and DELETE
 * methods. Uses the method {@link #setWriteMode(boolean)} to activate the
 * 'write-enabled' mode.
 * <p>
 * Resources can be created, retrieved, changed, and deleted locally through the
 * {@link #setResource(String,int,byte[])}, {@link #getResourceValue(String)},
 * and {@link #getResourceFormat(String)} methods.
 * <p>
 * For example, in order to create a server and add a resource you can simply
 * do:
 * <pre>
 * 	CoapServer server = new CoapServer();
 * 	server.setResource("/test",CoapResource.FORMAT_TEXT_PLAIN_UTF8,"Hello World!".getBytes());
 * </pre>
 * <p>
 */
public class CoapServer extends AbstractCoapServer {

    /**
     * Maximum resource size
     */
    private int MAXIMUM_RESOURCE_SIZE = 1024 * 1024;

    /**
     * Maximum number of resources
     */
    private int MAXIMUM_RESOURCE_NUMBER = 64;

    /**
     * Rate of reliable notifications (for testing the wakeness of the client)
     * in case of 'unreliable-notification' mode (actually it is the inverse of
     * the rate)
     */
    private static final int RELIABLE_NOTIFICATION_RATE = 10;

    /**
     * Write-enabled mode
     */
    boolean write_mode = false;

    /**
     * Whether notifications are reliable
     */
    boolean reliable_notification = true;

    /**
     * Resources (Hashtable<(String)name,(Resource)resource>)
     */
    Hashtable<String, CoapResource> resources = new Hashtable<String, CoapResource>();

    String Crypto_Alg = "RSA"; // RSA, RSA-AES
    boolean Encrypted;

    /**
     * Creates a new CoAP server.
     */
    public CoapServer() throws SocketException {
        super();
    }

    /**
     * Creates a new CoAP server.
     *
     * @param local_port CoAP UDP port
     */
    public CoapServer(int local_port) throws SocketException {
        super(local_port);
    }

    /**
     * Whether it is in write-enabled mode.
     *
     * @return <i>true</i> if write-enabled mode is active
     */
    public boolean isWriteMode() {
        return write_mode;
    }

    /**
     * Sets the write-enabled mode. It enables the support of CoAP method PUT
     * and DELETE.
     *
     * @param write_mode <i>true</i> to activate the write-enabled mode
     */
    public void setWriteMode(boolean write_mode) {
        this.write_mode = write_mode;
    }

    /**
     * Sets notification reliability.
     *
     * @param reliable_notification <i>true</i> if notifications are reliable
     */
    public void setReliableNotification(boolean reliable_notification) {
        this.reliable_notification = reliable_notification;
    }

    /**
     * Whether notifications are reliable.
     *
     * @return <i>true</i> if notifications are reliable
     */
    public boolean isReliableNotification() {
        return reliable_notification;
    }

    @Override
    public boolean respond(CoapRequest req, CoapResponse resp) {
        log("respond(): " + resp.getCodeAsString());
        // Crypto
        boolean success = super.respond(req, resp);

        if (!success) {
            log("respond(): no matching request has been found: response discarded");
        }
        return success;
    }

    @Override
    protected void handleGetRequest(CoapRequest req) {



        String resource_name = req.getRequestUriPath();
        log("handleGetRequest(): " + req.getCodeAsString() + " " + resource_name);
        if (resources.containsKey(resource_name)) {
            CoapResource resource = resources.get(resource_name);
            CoapResponse resp = CoapMessageFactory.createResponse(req, CoapResponseCode._2_05_Content);
            resp.setPayload(resource.getFormat(), resource.getValue());
            respond(req, resp);
        } else {
            CoapResponse resp = CoapMessageFactory.createResponse(req, CoapResponseCode._4_04_Not_Found);
            respond(req, resp);
        }
    }

    @Override
    protected void handlePutRequest(CoapRequest req) {
        String resource_name = req.getRequestUriPath();
        log("handlePutRequest(): " + req.getCodeAsString() + " " + resource_name);
        if (!write_mode) {
            log("handlePutRequest(): not in write mode");
            super.handlePutRequest(req);
            return;
        }
        // else
        byte[] resource_value = req.getPayload();
        if (resource_value != null && resource_value.length <= MAXIMUM_RESOURCE_SIZE) {
            CoapResponse resp = CoapMessageFactory.createResponse(req, CoapResponseCode._2_04_Changed);
            resp.setPayload(req.getContentFormat(), resource_value);
            respond(req, resp);
            setResource(resource_name, req.getContentFormat(), resource_value);
        } else {
            CoapResponse resp = CoapMessageFactory.createResponse(req, CoapResponseCode._4_13_Request_Entity_Too_Large);
            respond(req, resp);
        }
    }

    @Override
    protected void handleDeleteRequest(CoapRequest req) {
        String resource_name = req.getRequestUriPath();
        log("handleDeleteRequest(): " + req.getCodeAsString() + " " + resource_name);
        if (!write_mode) {
            log("handleDeleteRequest(): not in write mode");
            super.handleDeleteRequest(req);
            return;
        }
        // else
        if (resources.containsKey(resource_name)) {
            removeResource(resource_name);
            CoapResponse resp = CoapMessageFactory.createResponse(req, CoapResponseCode._2_02_Deleted);
            respond(req, resp);
        } else {
            CoapResponse resp = CoapMessageFactory.createResponse(req, CoapResponseCode._4_04_Not_Found);
            respond(req, resp);
        }
    }

    @Override
    protected void handleObserveRequest(CoapRequest req) {
        log("handleObserveRequest()");
        handleGetRequest(req);
        String resource_name = req.getRequestUriPath();
        if (resource_name == null) {
            return;
        }
        // else
        resources.get(resource_name).addObserveRequest(req);
    }

    @Override
    protected void handleObserveTerminated(CoapRequest req) {
        log("handleObserveTerminated()");
        String resource_name = req.getRequestUriPath();
        if (resource_name == null) {
            return;
        }
        // else
        resources.get(resource_name).removeObserveRequest(req);
    }

    /**
     * Gets the resource format.
     *
     * @param resource_name the resource name
     * @return the resource format
     */
    public int getResourceFormat(String resource_name) {
        return resources.get(resource_name).getFormat();
    }

    /**
     * Gets the resource value.
     *
     * @param resource_name the resource name
     * @return the resource value
     */
    public byte[] getResourceValue(String resource_name) {
        return resources.get(resource_name).getValue();
    }

    /**
     * Changes the resource value.
     *
     * @param name the resource name
     * @param value the new resource value
     */
    public void setResource(String name, byte[] value) {
        setResource(name, -1, value);
    }

    /**
     * Changes the resource value.
     *
     * @param name the resource name
     * @param format the resource format
     * @param value the new resource value
     */
    public synchronized void setResource(String name, int format, byte[] value) {
        log("setResource(): " + name + "," + format + "," + (value != null ? ByteUtils.asHex(value) : "void"));
        CoapResource resource;
        if (resources.containsKey(name)) {
            resource = resources.get(name);
            resource.setFormat(format);
            resource.setValue(value);
        } else {
            log("setResource(): new resource");
            resource = new CoapResource(name, format, value);
            resources.put(name, resource);
            if (resources.size() > MAXIMUM_RESOURCE_NUMBER) {
                log("setResource(): maximum number of resources has been exceeded: an old resource is removed randomly");
                //resources.remove(resources.elements().nextElement());
                removeResource(resources.elements().nextElement().getName());
            }
        }
        // notifies the new value to all observers
        int count = 0;
        for (Iterator<CoapRequest> i = resource.getObserveRequestIterator(); i.hasNext();) {
            CoapRequest req_i = i.next();
            log("setResource(): notify to: " + req_i.getRemoteSoAddress());
            CoapResponse resp_i = CoapMessageFactory.createResponse(req_i, CoapResponseCode._2_04_Changed);
            resp_i.setPayload(format, value);
            if (!reliable_notification && Random.nextInt(RELIABLE_NOTIFICATION_RATE) != 0) {
                resp_i.setType(CoapMessageType.NON);
            }
            respond(req_i, resp_i);
            count++;
        }
        log("setResource(): observers notified: " + count);
    }

    /**
     * Removes the resource value.
     *
     * @param name the resource name
     */
    public synchronized void removeResource(String name) {
        // notifies to all observers
        CoapResource resource = resources.get(name);
        if (resource != null) {
            for (Iterator<CoapRequest> i = resource.getObserveRequestIterator(); i.hasNext();) {
                CoapRequest req_i = i.next();
                log("removeResource(): notify to: " + req_i.getRemoteSoAddress());
                CoapResponse resp_i = CoapMessageFactory.createResponse(req_i, CoapResponseCode._4_04_Not_Found);
                respond(req_i, resp_i);
            }
            resources.remove(name);
        }
    }

    /**
     * Logs a message.
     */
    private void log(String str) {
        Logger logger = SystemUtils.getDefaultLogger();
        if (logger != null) {
            logger.log(LoggerLevel.INFO, getClass(), str);
        }
    }

    public void setCoapMessage(boolean Encryption, String Method) {
        Encrypted = Encryption;
        Crypto_Alg = Method;
    }

}
