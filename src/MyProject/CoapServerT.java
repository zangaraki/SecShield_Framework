/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package MyProject;

import it.unipr.netsec.mjcoap.coap.provider.CoapProvider;
import java.net.SocketException;
import it.unipr.netsec.mjcoap.coap.server.*;
import java.util.HashSet;
import org.zoolu.util.ByteUtils;

/**
 *
 * @author admin
 */
public class CoapServerT{

    public static void main(String[] args) throws SocketException {
        int local_port = CoapProvider.DEFAUL_PORT;
        HashSet<CoapResource> resources = new HashSet<CoapResource>();
        String[] resource_tuple = {"00248", "02468", "02468", ""};
        while (resource_tuple != null) {
            String resource_name = resource_tuple[0];
            int resource_format = CoapResource.getContentFormatIdentifier(resource_tuple[1]);
            String str = resource_tuple[2];
            byte[] resource_value = str.startsWith("0x") ? ByteUtils.hexToBytes(str) : str.getBytes();
            CoapResource res = new CoapResource(resource_name, resource_format, resource_value);
            resources.add(res);
            System.out.println("Adding server resource: " + res);
        }
        CoapServer server = new CoapServer(local_port);
        System.out.println("CoAP server running on port: " + local_port);

        server.halt();
    }

}
