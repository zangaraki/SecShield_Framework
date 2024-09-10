/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package MyProject;

import it.unipr.netsec.mjcoap.coap.client.CoapClient;
import it.unipr.netsec.mjcoap.coap.client.CoapResponseHandler;
import it.unipr.netsec.mjcoap.coap.message.CoapRequest;
import it.unipr.netsec.mjcoap.coap.message.CoapRequestMethod;
import it.unipr.netsec.mjcoap.coap.message.CoapResponse;
import it.unipr.netsec.mjcoap.coap.provider.CoapProvider;
import it.unipr.netsec.mjcoap.coap.provider.CoapURI;
import it.unipr.netsec.mjcoap.coap.server.CoapResource;
import java.net.SocketException;
import java.net.URISyntaxException;
import org.zoolu.util.ByteUtils;
import org.zoolu.util.SystemUtils;

/**
 *
 * @author admin
 */
public class CoapClientT{

    public static void main(String[] args) throws URISyntaxException, SocketException {
        int local_port = CoapProvider.DEFAUL_PORT;
        CoapClient client = new CoapClient(local_port);

        // handler for receiving the response
        CoapResponseHandler resp_handler = new CoapResponseHandler() {
            @Override
            public void onResponse(CoapRequest req, CoapResponse resp) {
                byte[] value = resp.getPayload();
                String format = CoapResource.getContentFormat(resp.getContentFormat());
                System.out.println("Response: " + resp.getResponseCode() + ": " + (format != null ? format + ": " : "") + (value != null ? new String(value) : "void"));
                if (!req.hasObserveRegister()) {
                    client.halt();
                    System.exit(0);
                }
            }

            @Override
            public void onRequestFailure(CoapRequest req) {
                if (req.hasObserveRegister()) {
                    System.out.println("Observation finished");
                } else {
                    System.out.println("Request failure");
                }
                client.halt();
                System.exit(0);
            }
        };

        // request                
        String method_name = "OBSERVE";
        String resource_uri = "coap://coap.me";//"coap://127.0.0.1/test";
//        String[] resource_tuple = flags.getStringTuple("-b", 2, "<format> <value>", null, "resource value in PUT or POST requests; format can be: NULL|TEXT|XML|JSON; value can be ASCII or HEX (0x..)");
        String[] resource_tuple = {"00248", "02468"};
        int resource_format = resource_tuple != null ? CoapResource.getContentFormatIdentifier(resource_tuple[0]) : -1;
        byte[] resource_value = resource_tuple != null ? (resource_tuple[1].startsWith("0x") ? ByteUtils.hexToBytes(resource_tuple[1]) : resource_tuple[1].getBytes()) : null;

        if (method_name.equalsIgnoreCase("OBSERVE")) { // method (e.g. GET, PUT, etc.)
            // resource observation
            CoapURI uri = new CoapURI(resource_uri);
            client.observe(uri, resp_handler);
            SystemUtils.readLine();
            client.observeCancel(uri);
        } else {
            // resource GET, PUT, POST, or DELETE
            client.request(CoapRequestMethod.getMethodByName(method_name), new CoapURI(resource_uri), resource_format, resource_value, resp_handler);
        }

        client.halt();
    }

}
