package lorentealberto.byss.ccpf;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.JTextArea;

/**
 *
 * @author Alberto Escribano Lorente
 */
public class Core {
    
    private final JTextArea consola;
    
    //private 
    //private 
    private KeyRing ring;
    //private 
    //private 
    //private 
    
    public Core(JTextArea consola) {
        this.consola = consola;
        detectarClaves();
    }
    
    /**
     *
     * @param file
     * @param algoritmo
     */
    public void firmar(File file, String algoritmo) {
        try {
            ByteArrayOutputStream baos;
            BufferedInputStream bis;
            FileOutputStream output;
            FileInputStream input;
            Signature firma;
            Header header;
            byte[] buffer;
            byte[] sig;
            int data;
            File f;

            firma = Signature.getInstance(algoritmo);
            firma.initSign(ring.getPrivate());
            input = new FileInputStream(file);
            bis = new BufferedInputStream(input);
            f = new File(file.getAbsolutePath() + ".raido");
            output = new FileOutputStream(f);
            baos = new ByteArrayOutputStream();
            buffer = new byte[1024];
            
            
            while ((data = bis.read(buffer)) >= 0)
                firma.update(buffer, 0, data);
            
            sig = firma.sign();
            bis.close();        
            header = new Header(algoritmo, sig);
            header.save(output);
            
            input = new FileInputStream(file);
            bis = new BufferedInputStream(input);
            buffer = new byte[1024];
            
            while ((data = bis.read(buffer)) >= 0)
                baos.write(buffer, 0, data);
            
            output.write(baos.toByteArray());
            output.flush();
            output.close();
            
            consola.append("\nArchivo firmado correctamente"
                    + "\nAlgoritmo usado: " + algoritmo
                    + "\nBytes de la firma: " + sig.length);
            
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Core.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            consola.append("\n Llave inválida");
            Logger.getLogger(Core.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Core.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Core.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            Logger.getLogger(Core.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /**
     *
     * @param file
     * @param algoritmo
     */
    public void verificarFirma(File file) {
        try {
            FileInputStream input;
            Signature firma;
            byte[] buffer;
            int data;
            Header header = new Header();
            
            input = new FileInputStream(file);
            
            try (BufferedInputStream binput = new BufferedInputStream(input)) {

                buffer = new byte[1024];
                header.load(input);
                firma = Signature.getInstance(header.getSigner());
                firma.initVerify(ring.getPublic());
               
                
                
                while(binput.available() != 0) {
                    data = binput.read(buffer);
                    firma.update(buffer, 0, data);
                }
            }
            
            if (firma.verify(header.getSign()))
                consola.append("\nLa firma del archivo es correcta.");
            else
                consola.append("\nLa firma no se corresponde con el fichero.");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Core.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            consola.append("\n Llave inválida");
            Logger.getLogger(Core.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Core.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Core.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            Logger.getLogger(Core.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /**
     *
     * @param file
     * @param algoritmo
     */
    public void cifrar(File file, String algoritmo) {
        try {
            Cipher c = Cipher.getInstance(algoritmo);
            c.init(Cipher.ENCRYPT_MODE, ring.getPublic());
            File f = new File(file.getAbsolutePath() + ".algiz");
            FileInputStream input;
            input = new FileInputStream(file);
            Header header = new Header(algoritmo);
            
            try (FileOutputStream output = new FileOutputStream(f)) {
                header.save(output);
                int blocksize = 53;
                byte[] data = new byte[blocksize];
                byte[] out;
                while (input.available() > 0)  {
                    input.read(data);
                    out = c.doFinal(data);
                    output.write(out);
                }
                
                output.flush();
                consola.append("\nArchivo: "+ f.getAbsolutePath() +" cifrado correctamente");
            }
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Core.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(Core.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            consola.append("\n Llave inválida");
            Logger.getLogger(Core.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Core.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Core.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(Core.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(Core.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        
    }
    
    public void descifrar(File file) {
        try {
            FileInputStream input = new FileInputStream(file);
            Header header = new Header();
            header.load(input);
            Cipher c = Cipher.getInstance(header.getCipher());
            c.init(Cipher.DECRYPT_MODE, ring.getPrivate());
            
            String path = file.getAbsolutePath();
            path = path.substring(0, path.lastIndexOf("."));
            
            
            File f = new File(path);
            try (FileOutputStream output = new FileOutputStream(f)) {
                int blockSize = 64;
                byte[] data = new byte[blockSize];
                byte[] out;
                
                while (input.available() > 0) {
                    input.read(data);
                    out = c.doFinal(data);
                    output.write(out);
                }
                
                output.flush();
                consola.append("\nArchivo desencriptado correctamente:"
                    + f.getAbsolutePath());
            }
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Core.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(Core.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            consola.append("\n Llave inválida");
            Logger.getLogger(Core.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Core.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Core.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(Core.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(Core.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /**
     * Si han sido generadas, muestra por pantalla las claves actuales
     */
    public void verClavesActuales() {
        if (clavesGeneradas()){
            consola.append("\nClaves actuales: \n"
                    + "Pública: " + ring.getPublic().toString() +"\n"
                    + "Privada: " + ring.getPublic().toString());
        } else
            consola.append("\nAún no se ha generado ninguna clave.");
    }
    
    /**
     * Genera un par de claves nuevas usando el algoritmo dado.
     * @param algoritmo Algoritmo utilizado para generar las claves
     */
    public void generarClaves(String algoritmo) {
        try {
            KeyPairGenerator generator;
            KeyPair pair;
            generator = KeyPairGenerator.getInstance(algoritmo);
            generator.initialize(512);
            pair = generator.generateKeyPair();
            ring = new KeyRing(pair.getPublic(), pair.getPrivate());
            consola.append("Clave generada: \n"
                    + "Pública: " + ring.getPublic().toString() +"\n"
                            + "Privada: " + ring.getPublic().toString());
            
            File f = new File("key.ring");
            FileOutputStream file = new FileOutputStream(f);
            try (ObjectOutputStream output = new ObjectOutputStream(file)) {
                output.writeObject(ring);
            }
            consola.append("\nEl llavero ha sido guardado correctamente " + f.getAbsolutePath());
        } catch (NoSuchAlgorithmException | IOException ex) {
            Logger.getLogger(Core.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /**
     * @return True si existe algún llavero
     */
    public boolean clavesGeneradas() {
        return (ring != null);
    }
    
    /**
     * Comprueba si hay algún llavero
     */
    private void detectarClaves() {
        try {
            File f = new File("key.ring");
            try (FileInputStream file = new FileInputStream(f); ObjectInputStream input = new ObjectInputStream(file)) {
                ring = (KeyRing) input.readObject();
                consola.append("Se ha detectado un llavero");
            }
        } catch (FileNotFoundException ex) {
            consola.append("No se ha detectado ningún llavero");
        } catch (IOException | ClassNotFoundException ex) {
            Logger.getLogger(Core.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}