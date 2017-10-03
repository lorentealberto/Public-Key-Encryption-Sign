package lorentealberto.byss.ccpf;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 *
 * @author Alberto Escribano Lorente
 */
public class KeyRing implements Serializable{
    
    private final PublicKey publicKey;
    private final PrivateKey privateKey;
    
    public KeyRing(PublicKey pb, PrivateKey pv) {
        publicKey = pb;
        privateKey = pv;
    }
    
    public PublicKey getPublic() {
        return publicKey;
    }
    
    public PrivateKey getPrivate() {
        return privateKey;
    }
}
