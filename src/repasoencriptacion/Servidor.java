
package repasoencriptacion;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;

public class Servidor {

    public static void main(String[] args) {
        SecretKey key = getSecretKey(128);
        String hash = obtenerHash(key.getEncoded());
        SSLServerSocket sslss = getSSLServerSocket("privada.pk12", "123qwe", 17000);
        while(true){
            aceptarPeticiones(sslss, key, hash);
        }
        
    }
    
    private static void aceptarPeticiones(SSLServerSocket server,
            SecretKey sk, String hash){
        try {
            Socket s = server.accept();
            Thread hilo = new Thread(new HiloServidor(sk, s, hash));
            hilo.start();
        } catch (IOException ex) {
            Logger.getLogger(Servidor.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private static SSLServerSocket getSSLServerSocket(String fileName, String passw, int puerto){
        SSLServerSocket s = null;
        try {
            KeyStore store = KeyStore.getInstance("pkcs12");
            store.load(new FileInputStream(new File(fileName)), passw.toCharArray());
            
            KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            factory.init(store, passw.toCharArray());
            
            SSLContext con = SSLContext.getInstance("TLS");
            con.init(factory.getKeyManagers(), null, null);
            s = (SSLServerSocket) con.getServerSocketFactory().createServerSocket(puerto);
            
        } catch (KeyStoreException ex) {
            Logger.getLogger(Servidor.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Servidor.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Servidor.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Servidor.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(Servidor.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnrecoverableKeyException ex) {
            Logger.getLogger(Servidor.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyManagementException ex) {
            Logger.getLogger(Servidor.class.getName()).log(Level.SEVERE, null, ex);
        }
        return s;
    }
    
    private static SecretKey getSecretKey(int longitud){
        SecretKey s = null;        
        try {
            KeyGenerator generador = KeyGenerator.getInstance("AES");
            generador.init(longitud, null);
            s = generador.generateKey();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Servidor.class.getName()).log(Level.SEVERE, null, ex);
        }
        return s;
    }
    
    private static String obtenerHash(byte [] mensaje){
        String hash = "";
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(mensaje);
            hash = Base64.getEncoder().encodeToString(md.digest());
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Servidor.class.getName()).log(Level.SEVERE, null, ex);
        }
        return hash;
    }
    
}
