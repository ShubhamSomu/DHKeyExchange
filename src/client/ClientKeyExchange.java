package client;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import utility.SimpleUtils;

public class ClientKeyExchange {

    private PublicKey publicKey;
    private PrivateKey privateKey;

    private KeyFactory keyFactory;
    private KeyPair keyPair;
    private KeyAgreement keyAgreement;
    private KeyPairGenerator keyPairGenerator;
    private X509EncodedKeySpec x509EncodedKeySpec;

    private byte[] commonSecret;

    public ClientKeyExchange() {
    }

    // receive server's key, init our key using server's key, send out pub key to server
    public String exchangeKeys(String pubKeyEnc) throws InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] decodedServerKey = SimpleUtils.decodeBase64(pubKeyEnc);
        try {
            publicKey = receivePublicKeyFromServer(decodedServerKey) ;

            //sender.sendPublicKey(getPublicKey());
            //System.out.println("Encoded Public key :- " + getPublicKey());
            doPhase(publicKey);
            this.commonSecret = keyAgreement.generateSecret();
            return SimpleUtils.sendClientPubKey(publicKey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException | InvalidKeyException e) {
            e.printStackTrace();
        }

        return null;
    }

    //1 after receiving pk
    public PublicKey receivePublicKeyFromServer(byte[] publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        keyFactory = KeyFactory.getInstance("dh");
        x509EncodedKeySpec = new X509EncodedKeySpec(publicKey);

        System.err.println("generating keys..");
        PublicKey serverPublicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        try {
            generateDHKeyPair(serverPublicKey);
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return serverPublicKey;
    }

    //2
    public DHParameterSpec retrieveDHParamFromPB(PublicKey key) {
        return ((DHPublicKey) key).getParams();
    }

    public DHParameterSpec retrieveDHParamFromPR(PrivateKey key) {
        return ((DHPrivateKey) key).getParams();
    }

    //3
    public void generateDHKeyPair(PublicKey serverPublicKey) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        DHParameterSpec DHParam = retrieveDHParamFromPB(serverPublicKey);

        keyPairGenerator = KeyPairGenerator.getInstance("dh");
        keyPairGenerator.initialize(DHParam);
        keyPair = keyPairGenerator.generateKeyPair();

        this.publicKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();
        System.err.println("\n\n\n");
        System.err.println("------------CLIENT CONFIGS STARTS ------------");
        System.err.println("pu: " + SimpleUtils.encodeBase64(publicKey.getEncoded()));
        System.err.println("pr: " + SimpleUtils.encodeBase64(privateKey.getEncoded()));

        System.err.println("------------CLIENT PUBLIC KEY CONFS ------------");
        System.err.println("PU: G: " + retrieveDHParamFromPB(publicKey).getG());
        System.err.println("PU: L: " + retrieveDHParamFromPB(publicKey).getL());
        System.err.println("PU: P:" + retrieveDHParamFromPB(publicKey).getP());

        System.err.println("------------CLIENT PRIVATE KEY CONFS ------------");
        System.err.println("PR: G: " + retrieveDHParamFromPR(privateKey).getG());
        System.err.println("PR: L: " + retrieveDHParamFromPR(privateKey).getL());
        System.err.println("PR: P:" + retrieveDHParamFromPR(privateKey).getP());

        System.err.println("------------CLIENT CONFIGS ENDS ------------");
        System.err.println("\n\n\n");
        try {
            initDHKeyAgreement();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    //4
    public void initDHKeyAgreement() throws NoSuchAlgorithmException, InvalidKeyException {
        this.privateKey = keyPair.getPrivate();

        keyAgreement = KeyAgreement.getInstance("dh");
        keyAgreement.init(privateKey);
    }

    public void doPhase(PublicKey publicKey) throws InvalidKeyException {
        keyAgreement.doPhase(publicKey, true);
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public SecretKeySpec getAESKey() {
        return SimpleUtils.generateAESKey(this.commonSecret);
    }

    public byte[] getCommonSecret(){ // should be hidden
        return this.commonSecret;
    }

/*    public String getEncodedCommonSecret() {
        PublicKey publicKey;

        // supply pub key of server here
        try {
            publicKey = receivePublicKeyFromServer(b) ;

            //sender.sendPublicKey(getPublicKey());
            System.out.println("Encoded Public key :- " + getPublicKey());
            doPhase(publicKey);
            this.commonSecret = keyAgreement.generateSecret();
            SimpleUtils.sendClientPubKey(publicKey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException | InvalidKeyException e) {
            e.printStackTrace();
        }

        return new String(Base64.getEncoder().encode(SimpleUtils.generateAESKey(commonSecret).getEncoded()));
    }*/

/*    @Override
    protected void onProgressUpdate(Integer... values) {
        super.onProgressUpdate(values);
        if(values[0] == 1) sender.closeDialogPublicKey();
        if(values[0] == 2) sender.openDialogKeyPair();

    }

    @Override
    protected void onPostExecute(String s) {
        sender.showPrivateKey(s);
    }*/

/*    public interface SendKey {

        void openDialogPublicKey();
        void closeDialogPublicKey();

        void openDialogKeyPair();
        void closeDialogKeyPair();

        void sendPublicKey(PublicKey publicKey);
        void sendError(String error);
        void showPrivateKey(String s);
    }*/

}


