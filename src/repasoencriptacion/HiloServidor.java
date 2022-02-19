
package repasoencriptacion;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class HiloServidor implements Runnable{

    SecretKey sk;
    Socket s;
    String hash;

    public HiloServidor(SecretKey sk, Socket s, String hash) {
        this.sk = sk;
        this.s = s;
        this.hash = hash;
    }
    
    @Override
    public void run() {
        BufferedReader recibir = getReader(s);
        BufferedWriter enviar = getWriter(s);
        
        enviarMensaje(hash, enviar);
        enviarMensaje(Base64.getEncoder().encodeToString(sk.getEncoded()),enviar);
        
        String mensaje = descrifrarString(sk, recibirMensaje(recibir));
        System.out.println(mensaje);
        mensaje = "Hola, aqui el servidor listos para las comunicaciones";
        
        enviarMensaje(crifrarString(sk, mensaje), enviar);
        
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
            Logger.getLogger(HiloServidor.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(HiloServidor.class.getName()).log(Level.SEVERE, null, ex);
        }
        return s;
    }
    
    private static BufferedReader getReader(Socket s){
        BufferedReader br = null;
        try {
            br = new BufferedReader(new InputStreamReader(s.getInputStream()));
        } catch (IOException ex) {
            Logger.getLogger(HiloServidor.class.getName()).log(Level.SEVERE, null, ex);
        }
        return br;
    }
    
    private static BufferedWriter getWriter(Socket s){
        BufferedWriter bw = null;
        try {
            bw = new BufferedWriter(new OutputStreamWriter(s.getOutputStream()));
        } catch (IOException ex) {
            Logger.getLogger(HiloServidor.class.getName()).log(Level.SEVERE, null, ex);
        }
        return  bw;
    }
}
