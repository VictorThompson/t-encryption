import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

public class AESexample {

  private String keySize;
  private Key aesKey;

  
  public AESexample () throws Exception{  

  }
  
  public void establishKeys(String keysize) throws Exception {
    
    KeyGenerator keyGenSingle = KeyGenerator.getInstance("AES");
    keyGenSingle.init(Integer.parseInt(keysize));
    this.aesKey = keyGenSingle.generateKey();
  
    this.keySize= Integer.toString(aesKey.getEncoded().length*8);
    
    
  }
  
  public byte[] encrypt(byte[] plainText) throws Exception {

    // get an AES cipher object and print the provider
    Cipher cipher = Cipher.getInstance("AES");
  
    // encrypt the plaintext using the public key
    cipher.init(Cipher.ENCRYPT_MODE, aesKey);
    return cipher.doFinal(plainText);

  }
  
  public byte[] decrypt(byte[] cipherText) throws Exception {

    // get an AES cipher object and print the provider
    Cipher cipher = Cipher.getInstance("AES");
  
    // decrypt the text using the private key
    cipher.init(Cipher.DECRYPT_MODE, aesKey);
    return cipher.doFinal(cipherText);

  }
  

  public String getKeySize() {
    return keySize;
  }


}