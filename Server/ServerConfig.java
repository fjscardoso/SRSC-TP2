package Server;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class ServerConfig {
    private String[] cipherSuites, TLSversions;
    private String authMode;

    public ServerConfig() throws IOException, SAXException, ParserConfigurationException {
        Document doc = loadConfig();

        this.cipherSuites = fill("ENABLEDCIPHERSUITES");
        this.TLSversions = fill("TLSVERSION");
        this.authMode = doc.getElementsByTagName("AUTHMODE").item(0).getTextContent();
    }

    private Document loadConfig() throws ParserConfigurationException, IOException, SAXException {
        File inputFile = new File("serverTLS.xml");
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.parse(inputFile);
        doc.getDocumentElement().normalize();

        return doc;

    }

    private String[] fill(String value) throws IOException, SAXException, ParserConfigurationException {
        NodeList nd = loadConfig().getElementsByTagName(value).item(0).getChildNodes();
        List<String> tmp = new <String>ArrayList();
        int size = 0;

        for (int i = 0; i < nd.getLength(); i++) {
            Node n = nd.item(i);
            if (n.getNodeName().equals("value")){
                tmp.add(nd.item(i).getTextContent());
                size++;
            }
        }

        String[] rst = new String[size];
        tmp.toArray(rst);
        return rst;

    }

    public String[] getCipherSuites() {
        return cipherSuites;
    }

    public String getAuthMode() {
        return authMode;
    }

    public String[] getTLSversions() {
        return TLSversions;
    }
}
