import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.Base64;
import java.util.Scanner;

public class Client {

    public static final String EXIT = "exit";
    public static final String ALL = "all";
    public static final String CREATE = "create";
    public static final String SEND = "send";
    public static final String RECEIVE = "recv";
    public static final String RECEIPT = "receipt";
    public static final String STATUS = "status";
    public static final String LIST = "list";
    public static final String NEW = "new";

    private static final String cipherMode = "RSA/None/NoPadding";
    private static Socket socket;
    private static Cipher authCipher1, authCipher2, sessionCipher;

    public static void main(String[] args) throws IOException, ClassNotFoundException, NoSuchProviderException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, CertificateException, SignatureException, KeyStoreException, ParseException, UnrecoverableKeyException {
        socket = new Socket("localhost", 9002);
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        authCipher1 = Cipher.getInstance("RSA/None/NoPadding", "BC");
        authCipher2 = Cipher.getInstance("RSA/None/NoPadding", "BC");

        Scanner in = new Scanner(System.in);
        String command = (in.nextLine()).toLowerCase();
        while (!command.equalsIgnoreCase(EXIT)) {
            if (!command.equals("")) {
                String[] cmd = command.split(" ");
                switch (cmd[0]) {
                    case ALL:
                        all(cmd[0], Integer.parseInt(cmd[1]));
                        break;
                    case NEW:
                        newMsgs(cmd[0], Integer.parseInt(cmd[1]));
                        break;
                    case CREATE:
                        create(cmd[0], Integer.parseInt(cmd[1]));
                        break;
                    case SEND:
                        String concat = cmd[3];
                        for(int i = 4; i < cmd.length; i++){
                            concat +=  " " +  cmd[i];}
                        send(cmd[0], Integer.parseInt(cmd[1]), Integer.parseInt(cmd[2]), concat);
                        break;
                    case RECEIVE:
                        receive(cmd[0], Integer.parseInt(cmd[1]), cmd[2]);
                        break;
                    case RECEIPT:
                        receipt(cmd[0], Integer.parseInt(cmd[1]), cmd[2], cmd[3]);
                        break;
                    case STATUS:
                        status(cmd[0], Integer.parseInt(cmd[1]), cmd[2]);
                        break;
                    case LIST:
                        list(cmd[0]);
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

    private static void all(String type, int user) throws IOException {
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

    private static void newMsgs(String type, int user) throws IOException {
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

    private static void create(String type, int user) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, KeyStoreException, CertificateException, ParseException, InvalidKeyException, SignatureException {

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

    private static void send(String type, int sender, int receiver, String msg) throws IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, NoSuchProviderException, SignatureException, NoSuchPaddingException {

        //Generate session key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
        keyGen.init(256); // for example
        SecretKey sessionKey = keyGen.generateKey();

        //Cifrar com chave de sessao
        sessionCipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
        sessionCipher.init(Cipher.ENCRYPT_MODE, sessionKey);
        byte[] sessionEncrypted = sessionCipher.doFinal(msg.getBytes());

        //Criar jsonObject com mensagem, parametros e chave
        JsonObject obj = new JsonObject();
        //obj.addProperty("content", Base64.getEncoder().encodeToString(sessionAndkey));
        obj.addProperty("key", Base64.getEncoder().encodeToString(sessionKey.getEncoded()));
        obj.addProperty("alg", "AES/ECB/PKCS5Padding");

        String msg64 = Base64.getEncoder().encodeToString(obj.toString().getBytes());

        //Get receiver certificate from keystore
        KeyStore keyStore = KeyStore.getInstance("JKS");
        FileInputStream stream = new FileInputStream("server.jks");
        keyStore.load(stream, "password".toCharArray());

        //Get private key from sender
        Key privKey = keyStore.getKey("user" + sender, "password".toCharArray());

        //Encrypt with senders private key
        authCipher1.init(Cipher.ENCRYPT_MODE, privKey);
        byte[] auth1 = authCipher1.doFinal(msg64.getBytes());

        //Get receiver certificate
        java.security.cert.Certificate[] user2 = keyStore.getCertificateChain("user" + receiver);

        //Veryify certificate with rootCA
        user2[0].verify(user2[1].getPublicKey());

        // Cifrar com chave publica do recetor, assinatura digital
        authCipher2.init(Cipher.ENCRYPT_MODE, user2[0].getPublicKey());
        byte[] authenticated = authCipher2.doFinal(auth1);

        //Append key to msg
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        outputStream.write( sessionEncrypted );
        outputStream.write( authenticated );

        byte sessionAndkey[] = outputStream.toByteArray();

        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        sha256_HMAC.init(sessionKey);
        byte[] copy = sha256_HMAC.doFinal(msg.getBytes());

        //Criar jsonObject com mensagem, parametros e chave
        JsonObject msgObj = new JsonObject();
        //obj.addProperty("content", Base64.getEncoder().encodeToString(sessionAndkey));
        msgObj.addProperty("content", Base64.getEncoder().encodeToString(sessionAndkey));
        msgObj.addProperty("size", sessionEncrypted.length);

        JsonWriter wrt = new JsonWriter(new OutputStreamWriter(socket.getOutputStream()));
        wrt.beginObject();
        wrt.name("type").value(type);
        wrt.name("src").value(sender);
        wrt.name("dst").value(receiver);
        wrt.name("msg").value(Base64.getEncoder().encodeToString(msgObj.toString().getBytes()));
        wrt.name("copy").value(Base64.getEncoder().encodeToString(copy));
        wrt.endObject();
        wrt.flush();

        JsonReader js = new JsonReader( new InputStreamReader( socket.getInputStream(), "UTF-8") );
        JsonElement data = new JsonParser().parse(js);
        if (data.isJsonObject())
            System.out.println(data.getAsJsonObject());
    }

    private static void receive(String type, int id, String msgId) throws IOException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, KeyStoreException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, UnrecoverableKeyException, NoSuchPaddingException {



        KeyStore keyStore = KeyStore.getInstance("JKS");
        FileInputStream stream = new FileInputStream("server.jks");
        keyStore.load(stream, "password".toCharArray());

        //Get user private key from keystore
        Key privKey = keyStore.getKey("user" + id, "password".toCharArray());

        String[] sender = msgId.split("_");

        //Get receiver certificate
        java.security.cert.Certificate[] user2 = keyStore.getCertificateChain("user" + sender[0]);

        //Veryify certificate with rootCA
        user2[0].verify(user2[1].getPublicKey());


        JsonWriter wrt = new JsonWriter(new OutputStreamWriter(socket.getOutputStream()));
        wrt.beginObject();
        wrt.name("type").value(type);
        wrt.name("id").value(id);
        wrt.name("msg").value(msgId);
        wrt.endObject();
        wrt.flush();

        JsonReader js = new JsonReader( new InputStreamReader( socket.getInputStream(), "UTF-8") );
        JsonElement data = new JsonParser().parse(js);

        if(data.getAsJsonObject().has("error")){
            System.err.println("User cannot access message");
            throw new RuntimeException();
        }

        //Get encryption parameters and key from jsonObject
        String msgAndParams = data.getAsJsonObject().get("result").getAsJsonArray().get(1).getAsString();

        //Decode JsonObject from base64
        byte[] msgDecoded = Base64.getDecoder().decode(msgAndParams);
        System.out.println(new String(msgDecoded));
        //Parse JsonObject with contents and params to decryption
        JsonObject msgAndParamsObj = new JsonParser().parse(new String(msgDecoded)).getAsJsonObject();

        //Decode contents from base64
        byte[] sessionAndKey = Base64.getDecoder().decode(msgAndParamsObj.get("content").getAsString());

        //Separate encrpyted message and key
        byte[] msg = new byte[msgAndParamsObj.get("size").getAsInt()];
        byte[] keyAndParams = new byte[sessionAndKey.length - msgAndParamsObj.get("size").getAsInt()];
        System.arraycopy(sessionAndKey,0,msg,0,msgAndParamsObj.get("size").getAsInt());
        System.arraycopy(sessionAndKey,msgAndParamsObj.get("size").getAsInt(),keyAndParams,0,sessionAndKey.length - msgAndParamsObj.get("size").getAsInt());

        //Initialize ciphers
        authCipher1.init(Cipher.DECRYPT_MODE, privKey);
        authCipher2.init(Cipher.DECRYPT_MODE, user2[0].getPublicKey());

        //Decrypt with private key from the receptor
        byte[] auth1 = authCipher1.doFinal(keyAndParams);

        //Decrypt with senders public key
        byte[] sessionParams = authCipher2.doFinal(auth1);

        //Decode JsonObject from base64
        byte[] keyAndParamsDecoded = Base64.getDecoder().decode(sessionParams);

        //Parse JsonObject with contents and params to decryption
        JsonObject keyParamsObj = new JsonParser().parse(new String(keyAndParamsDecoded)).getAsJsonObject();

        byte[] key = Base64.getDecoder().decode(keyParamsObj.get("key").getAsString());

        //Get session key
        SecretKey sessionKey = new SecretKeySpec(key, 0, key.length, "AES");

        //Init sessionCipher
        sessionCipher = Cipher.getInstance(keyParamsObj.get("alg").getAsString(), "BC");

        //Decrypt message with session key and print
        sessionCipher.init(Cipher.DECRYPT_MODE, sessionKey);
        byte[] decrypted = sessionCipher.doFinal(msg);
        System.out.println(new String(decrypted));

        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        sha256_HMAC.init(sessionKey);
        byte[] copy = sha256_HMAC.doFinal(decrypted);


        receipt("receipt", id, msgId, Base64.getEncoder().encodeToString(copy));
        //receipt("receipt", Integer.parseInt(sender[0]), sender[0] + "_" + msgId.split("_")[1], Base64.getEncoder().encodeToString(copy));
        //System.out.println(Integer.parseInt(sender[0]) + "\n"  + msgId + "\n" + Base64.getEncoder().encodeToString(copy));

    }

    private static void status(String type, int id, String msgId) throws IOException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, KeyStoreException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, UnrecoverableKeyException {
        JsonWriter wrt = new JsonWriter(new OutputStreamWriter(socket.getOutputStream()));
        wrt.beginObject();
        wrt.name("type").value(type);
        wrt.name("id").value(id);
        wrt.name("msg").value(msgId);
        wrt.endObject();
        wrt.flush();
        JsonReader js = new JsonReader( new InputStreamReader( socket.getInputStream(), "UTF-8") );
        JsonElement data = new JsonParser().parse(js);
        if (data.isJsonObject()) {
            JsonObject obj = data.getAsJsonObject().get("result").getAsJsonObject().get("receipts").getAsJsonArray().get(0).getAsJsonObject();
            if(!data.getAsJsonObject().get("result").getAsJsonObject().get("msg").getAsString().equals(obj.get("receipt").getAsString())) {
                System.err.println("Wrong receipt");
                throw new RuntimeException();
            }   else
                System.out.println("Receipts match");
        }


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

    private static void list(String type) throws IOException {
        JsonWriter wrt = new JsonWriter(new OutputStreamWriter(socket.getOutputStream()));
        wrt.beginObject();
        wrt.name("type").value(type);
        wrt.endObject();
        wrt.flush();
        //JsonReader js = new JsonReader( new InputStreamReader( socket.getInputStream(), "UTF-8") );
        //JsonElement data = new JsonParser().parse(js);
        //if (data.isJsonObject())
        //    System.out.println(data.getAsJsonObject());
    }


}
