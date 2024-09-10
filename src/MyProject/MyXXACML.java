
package MyProject;

import com.google.common.base.Objects;
import java.io.File;
import java.util.Map;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class MyXXACML {

public static boolean check(Map<String, String> attributes) {
NodeList nodeList = null;
try {
File file = new File("MyXACML.xml");
DocumentBuilder documentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
Document document = documentBuilder.parse(file);
System.out.println("Root element: " + document.getDocumentElement().getNodeName());
if (document.hasChildNodes()) {
nodeList = document.getChildNodes();
}
} catch (Exception e) {
System.out.println(e.getMessage());
return false;
}
for (int count = 0; count < nodeList.getLength(); count++) {
Node elemNode = nodeList.item(count);
if (elemNode.getNodeType() == Node.ELEMENT_NODE) {
if (elemNode.hasAttributes()) {
NamedNodeMap nodeMap = elemNode.getAttributes();
for (int i = 0; i < nodeMap.getLength(); i++) {
Node node = nodeMap.item(i);
if (attributes.containsKey(node.getNodeName()) && Objects.equal(node.getNodeValue(), attributes.get(node.getNodeName()))) {
return true;
}
}
}
if (elemNode.hasChildNodes()) {
if (checkChildNodes(elemNode.getChildNodes(), attributes)) {
return true;
}
}
}
}
return false;
}

private static boolean checkChildNodes(NodeList nodeList, Map<String, String> attributes) {
for (int count = 0; count < nodeList.getLength(); count++) {
Node elemNode = nodeList.item(count);
if (elemNode.getNodeType() == Node.ELEMENT_NODE) {
if (elemNode.hasAttributes()) {
NamedNodeMap nodeMap = elemNode.getAttributes();
for (int i = 0; i < nodeMap.getLength(); i++) {
Node node = nodeMap.item(i);
if (attributes.containsKey(node.getNodeName()) && Objects.equal(node.getNodeValue(), attributes.get(node.getNodeName()))) {
return true;
}
}
}
if (elemNode.hasChildNodes()) {
if (checkChildNodes(elemNode.getChildNodes(), attributes)) {
return true;
}
}
}
}
return false;
}
}
