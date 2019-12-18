package Server;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.net.ssl.*;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;

class Server {

    static public void
    waitForClients ( SSLServerSocket s ) {
        ServerControl registry = new ServerControl();

        try {
            while (true) {

                SSLSocket c = (SSLSocket) s.accept();
                ServerActions handler = new ServerActions( c, registry );
                new Thread( handler ).start ();
            }
        } catch ( Exception e ) {
            System.err.print( "Cannot use socket: " + e );
        }

    }

    public static void main ( String[] args ) throws ParserConfigurationException, SAXException, IOException {
        if (args.length < 1) {
            System.err.print( "Usage: port\n" );
            System.exit( 1 );
        }

        int port = Integer.parseInt( args[0] );
        ServerConfig config = new ServerConfig();


        try {
            //System.out.println(config.getTLSversions()[1]);
            String[] confciphersuites=config.getCipherSuites();
            String[] confprotocols=config.getTLSversions();

            System.setProperty("javax.net.ssl.keyStore", "server.jks");
            System.setProperty("javax.net.ssl.keyStorePassword", "password");
            System.setProperty("javax.net.ssl.trustStore", "server-trustStore.jks");
            System.setProperty("javax.net.ssl.trustStorePassword", "password");

            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream("server.jks"), "password".toCharArray());
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, "password".toCharArray());
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(kmf.getKeyManagers(), null, null);
            SSLServerSocketFactory ssf = sc.getServerSocketFactory();
            SSLServerSocket s
                    = (SSLServerSocket) ssf.createServerSocket(port);

            s.setEnabledProtocols(confprotocols);
            s.setEnabledCipherSuites(confciphersuites);
            if(config.getAuthMode().equals("CLIENT-SERVER")) {
                s.setNeedClientAuth(true);
                System.out.println("Client auhentication requested for mutual authentication");
            }

            //SSLServerSocket s = (SSLServerSocket) new ServerSocket( port, 5, InetAddress.getByName( "localhost" ) );
            System.out.print( "Started server on port " + port + "\n" );
            waitForClients( s);
        } catch (Exception e) {
            System.err.print( "Cannot open socket: " + e );
            System.exit( 1 );
        }

    }

}
