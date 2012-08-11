public class RSAexample {

  private String keySize;
  private KeyPair key;
  
  public RSAexample () throws Exception{  

  }
  
  public void establishKeys(String keysize) throws Exception {

    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");

    keyGen.initialize(Integer.parseInt(keysize));
    
    this.key = keyGen.generateKeyPair();
    this.keySize = Integer.toString(((RSAKey)key.getPublic()).getModulus().bitLength());

  }
    
  public byte[] encrypt(byte[] plainText) throws Exception {

    // get an RSA cipher object and print the provider
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
  
    // encrypt the plaintext using the public key
    cipher.init(Cipher.ENCRYPT_MODE, key.getPublic());
    return cipher.doFinal(plainText);
    
  }
  
  public byte[] decrypt(byte[] cipherText) throws Exception {
    
    // get an RSA cipher object and print the provider
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
  
    // decrypt the text using the private key
    cipher.init(Cipher.DECRYPT_MODE, key.getPrivate());
    return cipher.doFinal(cipherText);
  }

  public byte[] sign(byte[] plainText) throws Exception {
    
    Signature sig = Signature.getInstance("SHA1WithRSA");
    sig.initSign(key.getPrivate());
    sig.update(plainText);
    return sig.sign();
  }

  public boolean verify(byte[] plainText, byte[] signature) throws Exception {
    
    Signature sig = Signature.getInstance("SHA1WithRSA");
    sig.initVerify(key.getPublic());
    sig.update(plainText);
    try {
      if (sig.verify(signature)) {
        return true;
      }   else return false;
    } catch (SignatureException se) {
      System.out.println( "Signature failed" );
    }
    return false;
  }
  
  public String getKeySize() {
    return keySize;
  }
  
}