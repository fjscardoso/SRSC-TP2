import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.*;

public class Client {

    public static final String EXIT = "exit";
    public static final String ALL = "all";
    public static final String CREATE = "create";
    public static final String SEND = "send";
    public static final String RECEIVE = "recv";
    public static final String RECEIPT = "receipt";
    public static final String STATUS = "status";

    private static final String cipherMode = "RSA/None/NoPadding";
    private static Socket socket;
    private static Cipher cipher;

    private static Map<Integer, Map<String, Key>> map = new HashMap<>();

    public static void main(String[] args) throws IOException, ClassNotFoundException, NoSuchProviderException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException {
        socket = new Socket("localhost", 9000);
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        cipher = Cipher.getInstance(cipherMode, "BC");

        Scanner in = new Scanner(System.in);
        String command = (in.nextLine()).toLowerCase();
        while (!command.equalsIgnoreCase(EXIT)) {
            if (!command.equals("")) {
                String[] cmd = command.split(" ");
                switch (cmd[0]) {
                    case ALL:
                        function(cmd[0], Integer.parseInt(cmd[1]));
                        break;
                    case CREATE: ;
                        create(cmd[0], Integer.parseInt(cmd[1]));
                        break;
                    case SEND: ;
                        send(cmd[0], Integer.parseInt(cmd[1]), Integer.parseInt(cmd[2]), cmd[3], cmd[3]);
                        break;
                    case RECEIVE: ;
                        receiveOrStatus(cmd[0], Integer.parseInt(cmd[1]), cmd[2]);
                        break;
                    case RECEIPT: ;
                        receipt(cmd[0], Integer.parseInt(cmd[1]), cmd[2], cmd[3]);
                        break;
                    case STATUS: ;
                        receiveOrStatus(cmd[0], Integer.parseInt(cmd[1]), cmd[2]);
                        break;
                    case EXIT:
                        System.exit(1);
                    default:
                        break;
                }
            }
            command = in.nextLine();
        }
    }

    private static void function(String type, int user) throws IOException {
        JsonWriter wrt = new JsonWriter(new OutputStreamWriter(socket.getOutputStream()));
        wrt.beginObject();
        wrt.name("type").value(type);
        wrt.name("id").value(user);
        wrt.endObject();
        wrt.flush();
        JsonReader js = new JsonReader( new InputStreamReader( socket.getInputStream(), "UTF-8") );
        JsonElement data = new JsonParser().parse(js);
        if (data.isJsonObject())
            System.out.println(data.getAsJsonObject());
    }

    private static void create(String type, int user) throws IOException, NoSuchProviderException, NoSuchAlgorithmException {

        SecureRandom random= Utils.createFixedRandom();

        // Creation of keys (keypair)
        KeyPairGenerator generator= KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(1024, random);
        // generator.initialize(2048, random);
        // generator.initialize(8192, random);
        // generator.initialize(4096, random);

        KeyPair pair= generator.generateKeyPair();
        Key pubKey= pair.getPublic();
        Key privKey= pair.getPrivate();

        Map<String, Key> aux = new HashMap<>();
        aux.put("publicKey", pubKey);
        aux.put("privateKey", privKey);

        map.put(user, aux);

        System.out.println(map.size());

        JsonWriter wrt = new JsonWriter(new OutputStreamWriter(socket.getOutputStream()));
        wrt.beginObject();
        wrt.name("type").value(type);
        wrt.name("uuid").value(user);
        wrt.endObject();
        wrt.flush();
        JsonReader js = new JsonReader( new InputStreamReader( socket.getInputStream(), "UTF-8") );
        JsonElement data = new JsonParser().parse(js);
        if (data.isJsonObject())
            System.out.println(data.getAsJsonObject());
    }

    private static void send(String type, int sender, int receiver, String msg, String copy) throws IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        // Cifrar
        System.out.println(map.get(receiver).get("publicKey"));
        cipher.init(Cipher.ENCRYPT_MODE, map.get(receiver).get("publicKey"));

        byte[] cipherText = cipher.doFinal(Base64.getEncoder().encode(msg.getBytes()));

        JsonWriter wrt = new JsonWriter(new OutputStreamWriter(socket.getOutputStream()));
        wrt.beginObject();
        wrt.name("type").value(type);
        wrt.name("src").value(sender);
        wrt.name("dst").value(receiver);
        wrt.name("msg").value(Base64.getEncoder().encodeToString(cipherText));
        wrt.name("copy").value(copy);
        wrt.endObject();
        wrt.flush();
        JsonReader js = new JsonReader( new InputStreamReader( socket.getInputStream(), "UTF-8") );
        JsonElement data = new JsonParser().parse(js);
        if (data.isJsonObject())
            System.out.println(data.getAsJsonObject());
    }

    private static void receiveOrStatus(String type, int id, String msgId) throws IOException {
        JsonWriter wrt = new JsonWriter(new OutputStreamWriter(socket.getOutputStream()));
        wrt.beginObject();
        wrt.name("type").value(type);
        wrt.name("id").value(id);
        wrt.name("msg").value(msgId);
        wrt.endObject();
        wrt.flush();
        JsonReader js = new JsonReader( new InputStreamReader( socket.getInputStream(), "UTF-8") );
        JsonElement data = new JsonParser().parse(js);
        if (data.isJsonObject())
            System.out.println(data.getAsJsonObject());
    }

    private static void receipt(String type, int id, String msgId, String receipt) throws IOException {
        JsonWriter wrt = new JsonWriter(new OutputStreamWriter(socket.getOutputStream()));
        wrt.beginObject();
        wrt.name("type").value(type);
        wrt.name("id").value(id);
        wrt.name("msg").value(msgId);
        wrt.name("receipt").value(receipt);
        wrt.endObject();
        wrt.flush();
        //JsonReader js = new JsonReader( new InputStreamReader( socket.getInputStream(), "UTF-8") );
        //JsonElement data = new JsonParser().parse(js);
        //if (data.isJsonObject())
        //    System.out.println(data.getAsJsonObject());
    }



}
