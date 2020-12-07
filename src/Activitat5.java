import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Scanner;

public class Activitat5 {
    final static Xifrar xifrar = new Xifrar();


    public static void Activitat1_1() throws UnsupportedEncodingException {
        System.out.println();
        System.out.println("Activitat 1.1");
        System.out.println();
        Scanner sc = new Scanner(System.in);
        KeyPair keys = xifrar.randomGenerate(1024);
        System.out.println("Introdueix la paraula a xifrar ");
        String paraula = sc.nextLine();
        byte[] paraulaByte = paraula.getBytes();
        byte[] paraulaEncriptada = xifrar.encryptData( paraulaByte, keys.getPublic());
        String encriptedString = new String(xifrar.decryptData(paraulaEncriptada, keys.getPrivate()), "UTF-8");
        System.out.println("paraula xifrada amb la clau pública ---> " +new String(paraulaEncriptada));
        System.out.println();
        System.out.println("paraula desencriptada amb la clau privada ---> "+encriptedString);
        System.out.println();
    }


    public static void Activitat1_2() throws Exception {
        Scanner sc = new Scanner(System.in);
        //System.out.println("Introdueix la ruta del keyustore ");
        //"C:\\Users\\bilal\\.keystore"
        String keystorePath = "C:\\Users\\bilal\\.keystore";
        System.out.println("Introdueix la contrasenya del keystore");
        //"0123456789"
        String keystoreKey = sc.nextLine();
        KeyStore myKeystore = xifrar.loadKeyStore(keystorePath, keystoreKey);
        System.out.println();
        System.out.println("Activitat 1.i.2.1 tipus keystore");
        System.out.println(myKeystore.getType());
        System.out.println();
        System.out.println("Activitat 1.i.2.2 mida magatzem");
        System.out.println(myKeystore.size());
        System.out.println("Hi ha actualment "+ myKeystore.size() +" claus");
        System.out.println();
        System.out.println("Activitat 1.i.2.3 alias totes les claus");
        Enumeration<String> enumeration = myKeystore.aliases();
        while(enumeration.hasMoreElements()) {
            String alias = enumeration.nextElement();
            System.out.println("nom alias: " + alias);
            if(enumeration.equals(myKeystore.size()))
                break;
        }
        System.out.println();
        System.out.println();
        System.out.println("Activitat 1.i.2.4 certificat una de les claus");
        System.out.println(myKeystore.getCertificate("mykey"));
        System.out.println();
        System.out.println("Activitat 1.i.2.5 algoritme xifrat clau");
        System.out.println(myKeystore.getCertificate("mykey").getPublicKey().getAlgorithm());
        System.out.println();

        System.out.println("Activitar 1.ii");
        System.out.println("Crant clau simetrica y desant-la");
        SecretKey novaKey = xifrar.keygenKeyGeneration(128);
        KeyStore ks = myKeystore;
        KeyStore.SecretKeyEntry secretKeyEntry  = new KeyStore.SecretKeyEntry(novaKey);
        KeyStore.ProtectionParameter porotecParam = new KeyStore.PasswordProtection(keystoreKey.toCharArray());
        ks.setEntry("novaKey", secretKeyEntry, porotecParam);
        FileOutputStream fos = new FileOutputStream(keystorePath);
        ks.store(fos, keystoreKey.toCharArray());
        System.out.println();
        System.out.println();

    }
    public static void Activitat1_3() throws FileNotFoundException, CertificateException {
        System.out.println("Activitar 1.3 Obtenir clau publica d'un certificat");
        System.out.println(xifrar.getPublicKey("C:\\Users\\bilal\\Desktop\\jordi.cer"));
    }

    public static void Activitat1_4() throws Exception {
        KeyStore ks = xifrar.loadKeyStore("C:\\Users\\bilal\\.keystore", "0123456789");
        System.out.println(xifrar.getPublicKey(ks,"myKey", "0123456789" ));
        System.out.println();
        System.out.println();
    }

    public static void Activitat1_5(){
        System.out.println("Activitat 1.5");
        System.out.println("Veure la clau privada");
        KeyPair newKey = xifrar.randomGenerate(1024);
        PrivateKey privateKey = newKey.getPrivate();
        byte[] textComprobarSignatura ="Aquesta es la meva signarutra".getBytes();
        System.out.println( new String(xifrar.signData(textComprobarSignatura, privateKey)));
        System.out.println();
        System.out.println();
    }

    public static void Activitat1_6()  {
        System.out.println("Activitat 1.6");
        System.out.println("Comprobar validesa de la signatura");
        KeyPair newKey = xifrar.randomGenerate(1024);
        KeyPair newKey2 = xifrar.randomGenerate(1024);
        PublicKey publicKey2 = newKey2.getPublic();
        PrivateKey privateKey = newKey.getPrivate();
        PublicKey publicKey = newKey.getPublic();
        byte[] textComprobarSignatura ="Aquesta es la meva signarutra".getBytes();
        byte[] signatura = xifrar.signData(textComprobarSignatura,privateKey);
        boolean comprobarSignatura = xifrar.validateSignature(textComprobarSignatura, signatura, publicKey);
        if(comprobarSignatura){
            System.out.println("Validesa de la signatura correcte");
        }
        else{
            System.out.println("La validesa de la singatura no es correcte");
        }
        System.out.println();
        System.out.println();
    }

    public static void Activitat2(){
        System.out.println("Activitat 2 decryptWrappedData");
        KeyPair newKey = xifrar.randomGenerate(1024);
        System.out.println();
        String frase = "Misatge encriptat";
        byte[][] textEncriptat = xifrar.encryptWrappedData(frase.getBytes(), newKey.getPublic());
        byte[] textDesencriptat = xifrar.decryptWrappedData(textEncriptat, newKey.getPrivate());
        System.out.println("Misatge encriptat -----> "+textEncriptat);
        System.out.println("Misatge desencriptat -----> " +new String(textDesencriptat, StandardCharsets.UTF_8));


    }



    public static void main(String[] args) throws Exception {
        //Activitat1_1();
        //Activitat1_2();
        //Activitat1_3();
        //Activitat1_4();
        //Activitat1_5();
        //Activitat1_6();
        Activitat2();
    }
}
