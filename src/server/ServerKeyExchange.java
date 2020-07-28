package server;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import utility.SimpleUtils;

public class ServerKeyExchange {

    private X509EncodedKeySpec x509KeySpec;

    private KeyPairGenerator serverKeyPair;
    private KeyPair serverPair;
    private KeyAgreement serverKeyAgreement;
    private KeyFactory keyFactory;

    private PrivateKey privateKey;
    private PublicKey publicKey;

    private byte[] commonSecret;
    private static final String CLIENT_PUB_KEY = "clientPubKey";

/*    public KeyExchange(){
        init();
    }*/

/*
    public static void main(String[] args) throws Exception {
        ServerKeyExchange keyExchange = new ServerKeyExchange();
        keyExchange.init();
        // ReceiveMessage receiveMessage = new ReceiveMessage(keyExchange);
        //keyExchange.getAESKey();
        //receiveMessage.receiveMessage(ServerConstants.CLIENT_ENC_MSG);
    }
*/

    public void init() {
        try {
            generateDHKeyPair();
            initDHAgreement();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    //2
    public DHParameterSpec retrieveDHParamFromPB(PublicKey key) {
        return ((DHPublicKey) key).getParams();
    }

    public DHParameterSpec retrieveDHParamFromPR(PrivateKey key) {
        return ((DHPrivateKey) key).getParams();
    }

    public void generateDHKeyPair() throws NoSuchAlgorithmException {
        serverKeyPair = KeyPairGenerator.getInstance("dh");
        serverKeyPair.initialize(2048);

        serverPair = serverKeyPair.generateKeyPair();
        privateKey = serverPair.getPrivate();
        publicKey = serverPair.getPublic();
        System.err.println("\n\n\n");
        System.err.println("------------SERVER CONFIGS STARTS ------------");
        System.err.println("pu: " + SimpleUtils.encodeBase64(publicKey.getEncoded()));
        System.err.println("pr: " + SimpleUtils.encodeBase64(privateKey.getEncoded()));

        System.err.println("------------SERVER PUBLIC KEY CONFS ------------");
        System.err.println("PU: G: " + retrieveDHParamFromPB(publicKey).getG());
        System.err.println("PU: L: " + retrieveDHParamFromPB(publicKey).getL());
        System.err.println("PU: P:" + retrieveDHParamFromPB(publicKey).getP());

        System.err.println("------------SERVER PRIVATE KEY CONFS ------------");
        System.err.println("PR: G: " + retrieveDHParamFromPR(privateKey).getG());
        System.err.println("PR: L: " + retrieveDHParamFromPR(privateKey).getL());
        System.err.println("PR: P:" + retrieveDHParamFromPR(privateKey).getP());

        System.err.println("------------SERVER CONFIGS ENDS ------------");
        System.err.println("\n\n\n");
    }

    public void initDHAgreement() throws NoSuchAlgorithmException, InvalidKeyException {
        serverKeyAgreement = KeyAgreement.getInstance("dh");
        serverKeyAgreement.init(privateKey);
    }

    public String getPublicKeyEncoded() {
        return SimpleUtils.encodeBase64(publicKey.getEncoded());
    }

    public String getPrivateKeyEncoded() {
        return SimpleUtils.encodeBase64(privateKey.getEncoded());
    }

    public void receivePublicKeyFromClient(String publicKeyBase64) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {

        byte[] pubKeyDecoded = SimpleUtils.decodeBase64(publicKeyBase64);

        keyFactory = KeyFactory.getInstance("dh");
        x509KeySpec = new X509EncodedKeySpec(pubKeyDecoded);

        PublicKey publicKey1 = keyFactory.generatePublic(x509KeySpec);

        serverKeyAgreement.doPhase(publicKey1, true);

        this.commonSecret = serverKeyAgreement.generateSecret();

        System.out.println("Your common secret is: " + SimpleUtils.encodeBase64(getAESKey().getEncoded()));

        System.out.println("Secret: " + getCommonSecret());

    }

    public byte[] getCommonSecret() {
        return commonSecret;
    }

    public SecretKeySpec getAESKey() {

        return SimpleUtils.generateAESKey(commonSecret);
    }
}
