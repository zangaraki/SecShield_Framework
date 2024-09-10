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
package it.unipr.netsec.mjcoap.coap.client;

import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Hashtable;

import it.unipr.netsec.mjcoap.coap.blockwise.*;
import it.unipr.netsec.mjcoap.coap.message.*;
import it.unipr.netsec.mjcoap.coap.observe.*;
import it.unipr.netsec.mjcoap.coap.provider.*;
import it.unipr.netsec.mjcoap.coap.server.CoapResource;

/**
 * Simple CoAP client. It can be used to send CoAP GET, PUT, or DELETE requests
 * or to register for observing a remote resource, and to receive the
 * corresponding responses.
 * <p>
 * It supports resource observation (RFC 7641) and blockwise transfer (RFC
 * 7959).
 * <p>
 * The following code is a simple example of sending a request without
 * processing the corresponding response:
 * <pre>
 * 		CoapClient client = new CoapClient();
 * 		client.request(CoapRequestMethod.PUT,new URI("coap://127.0.0.1/test"),-1,"hello world".getBytes(),null);
 * </pre>
 * <p>
 * The responses can be received in either <i>non-blocking</i> mode or
 * <i>blocking</i> mode. The following code is an example of sending a request
 * and handling the response in non-blocking mode:
 * <pre>
 *  	CoapClient client = new CoapClient();
 *  	client.request(CoapRequestMethod.GET,new URI("coap://127.0.0.1/test"),new CoapResponseHandler() {
 *  		public void onResponse(CoapRequest req, CoapResponse resp) {
 *  			System.out.println("Response: "+resp);
 *  		}
 *  		public void onRequestFailure(CoapRequest req) {
 *  			System.out.println("Request failure");
 *  		}
 *  	});
 * </pre> Instead, the following code is an example of sending a request and
 * receiving the response in blocking mode:
 * <pre>
 * 		CoapClient client = new CoapClient();
 * 		CoapResponse resp=new CoapClient().request(CoapRequestMethod.GET,new URI("coap://127.0.0.1/test"));
 * 		if (resp!=null) System.out.println("Response: "+resp);
 * 		else System.out.println("Request failure");
 * </pre>
 */
public class CoapClient {

    /**
     * CoAP messaging layer
     */
    protected CoapProvider coap_provider;

    /**
     * Maximum block size
     */
    protected int max_block_size = 0;

    String Crypto_Alg = "RSA"; // RSA, RSA-AES
    boolean Encrypted;
    
    /**
     * Table of observe clients
     */
    Hashtable<CoapURI, ObserveTransactionClient> observe_clients = new Hashtable<CoapURI, ObserveTransactionClient>();

    /**
     * Creates a new CoAP client.
     */
    public CoapClient() throws SocketException {
        this(-1);
    }

    /**
     * Creates a new CoAP client.
     *
     * @param local_port the local CoAP port
     */
    public CoapClient(int local_port) throws SocketException {
        this(new DatagramSocket(local_port <= 0 ? CoapProvider.DYNAMIC_PORT : local_port));    
    }

    /**
     * Creates a new CoAP client.
     *
     * @param socket the UDP socket
     */
    public CoapClient(DatagramSocket socket) throws SocketException {
        coap_provider = new CoapProvider(socket);
    }

    /**
     * Sets the maximum block size.
     *
     * @param max_block_size the maximum block size
     */
    public void setMaximumBlockSize(int max_block_size) {
        this.max_block_size = max_block_size;
    }

    /**
     * Sends a request for a remote resource.
     *
     * @param method the request method
     * @param resource_uri the resource URI
     * @param resp_handler the handler of the response
     */
    public void request(CoapRequestMethod method, CoapURI resource_uri, CoapResponseHandler resp_handler) {
        request(method, resource_uri, -1, (byte[]) null, resp_handler);
    }

    /**
     * Sends a request for a remote resource.
     *
     * @param method the request method
     * @param resource_uri the resource URI
     * @param format the resource value format
     * @param resp_handler the handler of the response
     */
    public void request(CoapRequestMethod method, CoapURI resource_uri, int format, CoapResponseHandler resp_handler) {
        request(method, resource_uri, format, (byte[]) null, resp_handler);
    }

    /**
     * Sends a request for a remote resource.
     *
     * @param method the request method
     * @param resource_uri the resource URI
     * @param format the resource value format
     * @param resource_value the resource value
     */
    public void request(CoapRequestMethod method, CoapURI resource_uri, int format, byte[] resource_value, CoapResponseHandler resp_handler) {
        InetSocketAddress server_soaddr = new CoapSocketAddress(resource_uri.getHost(), resource_uri.getPort());
        CoapRequest req = CoapMessageFactory.createCONRequest(method, resource_uri);
        if (format >= 0) {
            req.setContentFormat(format);
        }
        if (resource_value != null) {
            req.setPayload(resource_value);
        }
        request(req, server_soaddr, resp_handler);
    }

    /**
     * Sends a request message.
     *
     * @param req the request message
     * @param server_soaddr the server address
     * @param resp_handler the handler of the response
     */
    public void request(CoapRequest req, InetSocketAddress server_soaddr, final CoapResponseHandler resp_handler) {
        BlockwiseTransactionClientListener tc_listener = new BlockwiseTransactionClientListener() {
            @Override
            public void onTransactionResponse(BlockwiseTransactionClient tc, CoapResponse resp) {
                resp_handler.onResponse(tc.getRequestMessage(), resp);
            }

            @Override
            public void onTransactionFailure(BlockwiseTransactionClient tc) {
                resp_handler.onRequestFailure(tc.getRequestMessage());
            }
        };
        BlockwiseTransactionClient tc = new BlockwiseTransactionClient(coap_provider, req, server_soaddr, tc_listener);
        if (max_block_size > 0) {
            tc.setMaximumBlockSize(max_block_size);
        }
        tc.request();
    }

    /**
     * Sends a request for a remote resource and receives the response. This is
     * a blocking method. It waits until a response is received or an error
     * occurs.
     *
     * @param method the request method
     * @param resource_uri the resource URI
     * @return the response
     */
    public CoapResponse request(CoapRequestMethod method, CoapURI resource_uri) {
        return request(method, resource_uri, -1, (byte[]) null);
    }

    /**
     * Sends a request for a remote resource and receives the response. This is
     * a blocking method. It waits until a response is received or an error
     * occurs.
     *
     * @param method the request method
     * @param resource_uri the resource URI
     * @param format the resource value format
     * @return the response
     */
    public CoapResponse request(CoapRequestMethod method, CoapURI resource_uri, int format) {
        return request(method, resource_uri, format, (byte[]) null);
    }

    /**
     * Sends a request for a remote resource and receives the response. This is
     * a blocking method. It waits until a response is received or an error
     * occurs.
     *
     * @param method the request method
     * @param resource_uri the resource URI
     * @param format the resource value format
     * @return the response
     */
    public CoapResponse request(CoapRequestMethod method, CoapURI resource_uri, int format, byte[] resource_value) {
        InetSocketAddress server_soaddr = new CoapSocketAddress(resource_uri.getHost(), resource_uri.getPort());
        CoapRequest req = CoapMessageFactory.createCONRequest(method, resource_uri);
        if (format >= 0) {
            req.setContentFormat(format);
        }
        if (resource_value != null) {
            req.setPayload(resource_value);
        }
        return request(req, server_soaddr);
    }

    /**
     * Sends a request message and receive the response. This is a blocking
     * method. It waits until a response is received or an error occurs.
     *
     * @param req the request message
     * @param server_soaddr the server address
     * @return the response
     */
    public CoapResponse request(CoapRequest req, InetSocketAddress server_soaddr) {
        if (server_soaddr == null) {
            throw new IllegalArgumentException("The socket address can't be null");
        }
        if (server_soaddr.getAddress() == null) {
            throw new IllegalArgumentException("The host address can't be null");
        }
        CoapResponse resp = null;
        final ArrayList<CoapResponse> receiver = new ArrayList<CoapResponse>();
        CoapResponseHandler resp_handler = new CoapResponseHandler() {
            @Override
            public void onResponse(CoapRequest req, CoapResponse resp) {
                synchronized (receiver) {
                    receiver.add(resp);
                    receiver.notifyAll();
                }
            }

            @Override
            public void onRequestFailure(CoapRequest req) {
                synchronized (receiver) {
                    receiver.notifyAll();
                }
            }
        };
        synchronized (receiver) {
            request(req, server_soaddr, resp_handler);
            try {
                receiver.wait();
            } catch (InterruptedException e) {
            }
            if (receiver.size() > 0) {
                resp = receiver.get(0);
                receiver.remove(0);
            }

        }
        return resp;
    }

    /**
     * Observes a remote resource.
     *
     * @param resource_uri the resource URI
     * @param resp_handler the handler of the responses (notification messages)
     */
    public void observe(CoapURI resource_uri, CoapResponseHandler resp_handler) {
        observe(resource_uri, -1, resp_handler);
    }

    /**
     * Observes a remote resource.
     *
     * @param resource_uri the resource URI
     * @param format the resource value format
     * @param resp_handler the handler of the responses (notification messages)
     */
    public void observe(CoapURI resource_uri, int format, CoapResponseHandler resp_handler) {
        InetSocketAddress server_soaddr = new CoapSocketAddress(resource_uri.getHost(), resource_uri.getPort());
        CoapRequest req = CoapMessageFactory.createCONRequest(CoapRequestMethod.GET, resource_uri);
        if (format >= 0) {
            req.setContentFormat(format);
        }
        observe(req, server_soaddr, resp_handler);
    }

    /**
     * Observes a remote resource.
     *
     * @param req the observe request message
     * @param server_soaddr the server address
     * @param resp_handler the handler of the responses (notification messages)
     */
    public synchronized void observe(CoapRequest req, InetSocketAddress server_soaddr, final CoapResponseHandler resp_handler) {
        ObserveTransactionClientListener oc_listener = new ObserveTransactionClientListener() {
            @Override
            public void onObserveNotification(ObserveTransactionClient observe_client, CoapResponseCode resp_code, byte[] state, int seq_num, CoapResponse resp) {
                resp_handler.onResponse(observe_client.getRequest(), resp);
            }

            @Override
            public void onObserveClientTerminated(ObserveTransactionClient observe_client) {
                resp_handler.onRequestFailure(observe_client.getRequest());
            }
        };
        ObserveTransactionClient oc = new ObserveTransactionClient(coap_provider, req, server_soaddr, oc_listener);
        CoapURI resource_uri = oc.getResourceURI();
        if (observe_clients.containsKey(resource_uri)) {
            observeCancel(resource_uri);
        }
        observe_clients.put(resource_uri, oc);
        oc.observe();
    }

    /**
     * Stops observing a remote resource.
     *
     * @param resource_uri the URI of the observed resource
     */
    public synchronized void observeCancel(CoapURI resource_uri) {
        if (observe_clients.containsKey(resource_uri)) {
            ObserveTransactionClient oc = observe_clients.get(resource_uri);
            observe_clients.remove(resource_uri);
            oc.cancel();
        }
    }

    /**
     * Stops the client.
     */
    public synchronized void halt() {
        for (Enumeration<ObserveTransactionClient> i = observe_clients.elements(); i.hasMoreElements();) {
            i.nextElement().cancel();
        }
        observe_clients.clear();
        coap_provider.halt();
    }

    public void setCoapMessage(boolean Encryption, String Method) {
        Encrypted = Encryption;
        Crypto_Alg = Method;
    }
    
    
}
