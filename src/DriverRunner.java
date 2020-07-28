import static utility.SimpleUtils.CLIENT_MSG;
import static utility.SimpleUtils.SERVER_MSG;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import client.ClientKeyExchange;
import server.ServerKeyExchange;
import utility.SimpleUtils;
import utility.SimpleUtils.*;

public class DriverRunner {

    public static void main(String[] args) throws Exception {
        ServerKeyExchange serverKeyExchange = new ServerKeyExchange();
        serverKeyExchange.init();

        String pubKeyEnc = serverKeyExchange.getPublicKeyEncoded();
        System.out.println("Server pub key ENC :  " + pubKeyEnc);
        //System.err.println("SERVER PRIVATE KEY :"+ serverKeyExchange.getAESKey().getEncoded());

        ClientKeyExchange clientKeyExchange = new ClientKeyExchange();

        String clientPubKeyEnc = clientKeyExchange.exchangeKeys(pubKeyEnc);

        serverKeyExchange.receivePublicKeyFromClient(clientPubKeyEnc);

        //System.err.println("SERVER PRIVATE KEY :"+ new String(serverKeyExchange.getAESKey().getEncoded()));

        //System.out.println("CLIENT Common Secret :- "+ new String(clientKeyExchange.getCommonSecret()));
        //System.out.println("SERVER Common Secret :- "+ new String(serverKeyExchange.getCommonSecret()));

/*        String encClientMsg = SimpleUtils.encrypt(CLIENT_MSG, clientKeyExchange.getAESKey());
        System.out.println("PLAIN CLIENT MSG:- "+ CLIENT_MSG);
        System.out.println("ENC CLIENT MSG:- "+ encClientMsg);

        String decClientMsg = SimpleUtils.decrypt(encClientMsg, serverKeyExchange.getAESKey());
        System.out.println("SERVER-DEC CLIENT MSG:- "+ decClientMsg);*/

        String encServerMsg = SimpleUtils.encrypt(SERVER_MSG, serverKeyExchange.getAESKey());
        System.out.println("PLAIN CLIENT MSG:- "+ SERVER_MSG);
        System.out.println("ENC CLIENT MSG:- "+ encServerMsg);

        String decServerMsg = SimpleUtils.decrypt(encServerMsg, clientKeyExchange.getAESKey());
        System.out.println("CLIENT-DEC SERVER MSG:- "+ decServerMsg);
    }
}
