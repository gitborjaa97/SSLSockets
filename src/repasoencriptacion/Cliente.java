
package repasoencriptacion;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

public class Cliente {
    
    public static void main(String[] args) {
        SSLSocket s = getSocket("127.0.0.1", 17000, "publica.pk12", "123qwe");
        BufferedReader br = getReader(s);
        BufferedWriter bw = getWriter(s);
        
        String hash = recibirMensaje(br);
        SecretKey key = sacarSecretKey(recibirMensaje(br));
        if(hash.equals(obtenerHash(key.getEncoded()))){
            System.out.println("Tenemos la clave correcta");
            String mensaje = "Hola, esta comunicacion es muy segura";
            enviarMensaje(crifrarString(key, mensaje), bw);
            
            System.out.println(descrifrarString(key, recibirMensaje(br)));
            
        }else
            System.out.println("¡Corred insensatos!, la clave ha sido alterada");
    }
    
    private static SSLSocket getSocket(String ip, int puerto,String almacen, String passw){
        SSLSocket s = null;
        try {
            KeyStore store = KeyStore.getInstance("pkcs12");
            store.load(new FileInputStream(new File(almacen)), passw.toCharArray());
            
            TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trust.init(store);
            SSLContext con = SSLContext.getInstance("TLS");
            con.init(null, trust.getTrustManagers(), null);
            s = (SSLSocket) con.getSocketFactory().createSocket(InetAddress.getByName(ip), puerto);
            
        } catch (KeyStoreException ex) {
            Logger.getLogger(Cliente.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Cliente.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Cliente.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Cliente.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(Cliente.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyManagementException ex) {
            Logger.getLogger(Cliente.class.getName()).log(Level.SEVERE, null, ex);
        }
        return s;
    }
    
    
    private static BufferedReader getReader(SSLSocket s){
        BufferedReader br = null;
        try {
            br = new BufferedReader(new InputStreamReader(s.getInputStream()));
        } catch (IOException ex) {
            Logger.getLogger(HiloServidor.class.getName()).log(Level.SEVERE, null, ex);
        }
        return br;
    }
    
    private static BufferedWriter getWriter(SSLSocket s){
        BufferedWriter bw = null;
        try {
            bw = new BufferedWriter(new OutputStreamWriter(s.getOutputStream()));
        } catch (IOException ex) {
            Logger.getLogger(HiloServidor.class.getName()).log(Level.SEVERE, null, ex);
        }
        return  bw;
    }
    
    private static SecretKey sacarSecretKey(String claveBase64){
        return new SecretKeySpec(Base64.getDecoder().decode(claveBase64), "AES");
    }
    
    private static String recibirMensaje(BufferedReader br){
        String s = "";
        try {
            s = br.readLine();
        } catch (IOException ex) {
            Logger.getLogger(HiloServidor.class.getName()).log(Level.SEVERE, null, ex);
        }
        return s;
    }
    
    private static void enviarMensaje(String mensaje, BufferedWriter bw){
        try {
            bw.write(mensaje +"\n");
            bw.flush();
        } catch (IOException ex) {
            Logger.getLogger(HiloServidor.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private static String crifrarString(SecretKey clave, String mensaje){
        String s = "";
        try {
            Cipher c = Cipher.getInstance(clave.getAlgorithm());
            c.init(Cipher.ENCRYPT_MODE, clave);
            s = Base64.getEncoder().encodeToString(c.doFinal(mensaje.getBytes()));
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Servidor.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(Servidor.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Servidor.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(Servidor.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(Servidor.class.getName()).log(Level.SEVERE, null, ex);
        }
        return s;
    }
    
    private static String descrifrarString(SecretKey clave, String mensajeBase64){
        String s = "";
        try {
            byte[] mensajeCifrado = Base64.getDecoder().decode(mensajeBase64);
            Cipher c = Cipher.getInstance(clave.getAlgorithm());
            c.init(Cipher.DECRYPT_MODE, clave);
            s = new String(c.doFinal(mensajeCifrado));            
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Servidor.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(Servidor.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Servidor.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(Cliente.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(Cliente.class.getName()).log(Level.SEVERE, null, ex);
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
