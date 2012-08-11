import javax.crypto.*;

public class Drive {

  /**
   * @param args
   */
  public static void main(String[] args) throws Exception{
    
      KeyGenerator keyGenSingle = KeyGenerator.getInstance("AES");
      keyGenSingle.init(256);
      byte[] plainText = keyGenSingle.generateKey().getEncoded();

//    SecureRandom random = new SecureRandom();
//      byte[] plainText = new byte[39];
//      random.nextBytes(plainText);
      
      Generator G;
      System.out.println("Algorithm | Key size  | Key (s)     | Encrypt (s) | Decrypt (s) | Sign (s)    | Verify (s)  | Total (s)   | # of Runs  | Match? | Verified? " );
      System.out.println("-----------------------------------------------------------------------------------------------------");

      G = new Generator ("RSA", "1024", plainText, 10);  
      System.out.println(G.getAlgorithm()+"       | "+G.getKeySize()+"      | "+G.getKeyTimeFormatted()+" | "+G.getEncryptTimeFormatted()+" | "+G.getDecryptTimeFormatted()+" | "+G.getSignTimeFormatted()+" | "+G.getVerifyTimeFormatted()+" | "+G.getTotalTimeFormatted()+" | "+G.getRepeat()+" | "+G.isMatch()+" | "+G.isVerified());
      G = new Generator ("ECIES", "secp160r1", plainText, 10);  
      System.out.println(G.getAlgorithm()+"     | "+G.getKeySize()+" | "+G.getKeyTimeFormatted()+" | "+G.getEncryptTimeFormatted()+" | "+G.getDecryptTimeFormatted()+" | "+G.getSignTimeFormatted()+" | "+G.getVerifyTimeFormatted()+" | "+G.getTotalTimeFormatted()+" | "+G.getRepeat()+" | "+G.isMatch()+" | "+G.isVerified());
      G = new Generator ("T", "secp160r1", plainText, 10);  
      System.out.println(G.getAlgorithm()+"         | "+G.getKeySize()+" | "+G.getKeyTimeFormatted()+" | "+G.getEncryptTimeFormatted()+" | "+G.getDecryptTimeFormatted()+" | "+G.getSignTimeFormatted()+" | "+G.getVerifyTimeFormatted()+" | "+G.getTotalTimeFormatted()+" | "+G.getRepeat()+" | "+G.isMatch()+" | "+G.isVerified());
      G = new Generator ("T", "secp160k1", plainText, 10);  
      System.out.println(G.getAlgorithm()+"         | "+G.getKeySize()+" | "+G.getKeyTimeFormatted()+" | "+G.getEncryptTimeFormatted()+" | "+G.getDecryptTimeFormatted()+" | "+G.getSignTimeFormatted()+" | "+G.getVerifyTimeFormatted()+" | "+G.getTotalTimeFormatted()+" | "+G.getRepeat()+" | "+G.isMatch()+" | "+G.isVerified());
      System.out.println("");
      G = new Generator ("RSA", "2048", plainText, 10);  
      System.out.println(G.getAlgorithm()+"       | "+G.getKeySize()+"      | "+G.getKeyTimeFormatted()+" | "+G.getEncryptTimeFormatted()+" | "+G.getDecryptTimeFormatted()+" | "+G.getSignTimeFormatted()+" | "+G.getVerifyTimeFormatted()+" | "+G.getTotalTimeFormatted()+" | "+G.getRepeat()+" | "+G.isMatch()+" | "+G.isVerified());
      G = new Generator ("ECIES", "secp224r1", plainText, 10);  
      System.out.println(G.getAlgorithm()+"     | "+G.getKeySize()+" | "+G.getKeyTimeFormatted()+" | "+G.getEncryptTimeFormatted()+" | "+G.getDecryptTimeFormatted()+" | "+G.getSignTimeFormatted()+" | "+G.getVerifyTimeFormatted()+" | "+G.getTotalTimeFormatted()+" | "+G.getRepeat()+" | "+G.isMatch()+" | "+G.isVerified());
      G = new Generator ("T", "secp224r1", plainText, 10);  
      System.out.println(G.getAlgorithm()+"         | "+G.getKeySize()+" | "+G.getKeyTimeFormatted()+" | "+G.getEncryptTimeFormatted()+" | "+G.getDecryptTimeFormatted()+" | "+G.getSignTimeFormatted()+" | "+G.getVerifyTimeFormatted()+" | "+G.getTotalTimeFormatted()+" | "+G.getRepeat()+" | "+G.isMatch()+" | "+G.isVerified());
      G = new Generator ("T", "secp224k1", plainText, 10);  
      System.out.println(G.getAlgorithm()+"         | "+G.getKeySize()+" | "+G.getKeyTimeFormatted()+" | "+G.getEncryptTimeFormatted()+" | "+G.getDecryptTimeFormatted()+" | "+G.getSignTimeFormatted()+" | "+G.getVerifyTimeFormatted()+" | "+G.getTotalTimeFormatted()+" | "+G.getRepeat()+" | "+G.isMatch()+" | "+G.isVerified());
      System.out.println("");
      G = new Generator ("RSA", "7680", plainText, 1);  
      System.out.println(G.getAlgorithm()+"       | "+G.getKeySize()+"      | "+G.getKeyTimeFormatted()+" | "+G.getEncryptTimeFormatted()+" | "+G.getDecryptTimeFormatted()+" | "+G.getSignTimeFormatted()+" | "+G.getVerifyTimeFormatted()+" | "+G.getTotalTimeFormatted()+" | "+G.getRepeat()+" | "+G.isMatch()+" | "+G.isVerified());
      G = new Generator ("AES", "192", plainText, 100);  
      System.out.println(G.getAlgorithm()+"       | "+G.getKeySize()+"       | "+G.getKeyTimeFormatted()+" | "+G.getEncryptTimeFormatted()+" | "+G.getDecryptTimeFormatted()+" | "+G.getSignTimeFormatted()+" | "+G.getVerifyTimeFormatted()+" | "+G.getTotalTimeFormatted()+" | "+G.getRepeat()+" | "+G.isMatch()+" | "+G.isVerified());
      G = new Generator ("ECIES", "secp384r1", plainText, 10);  
      System.out.println(G.getAlgorithm()+"     | "+G.getKeySize()+" | "+G.getKeyTimeFormatted()+" | "+G.getEncryptTimeFormatted()+" | "+G.getDecryptTimeFormatted()+" | "+G.getSignTimeFormatted()+" | "+G.getVerifyTimeFormatted()+" | "+G.getTotalTimeFormatted()+" | "+G.getRepeat()+" | "+G.isMatch()+" | "+G.isVerified());
      G = new Generator ("T", "secp384r1", plainText, 10);  
      System.out.println(G.getAlgorithm()+"         | "+G.getKeySize()+" | "+G.getKeyTimeFormatted()+" | "+G.getEncryptTimeFormatted()+" | "+G.getDecryptTimeFormatted()+" | "+G.getSignTimeFormatted()+" | "+G.getVerifyTimeFormatted()+" | "+G.getTotalTimeFormatted()+" | "+G.getRepeat()+" | "+G.isMatch()+" | "+G.isVerified());
      System.out.println("");     
      G = new Generator ("RSA", "15360", plainText, 1);  
      System.out.println(G.getAlgorithm()+"       | "+G.getKeySize()+"     | "+G.getKeyTimeFormatted()+" | "+G.getEncryptTimeFormatted()+" | "+G.getDecryptTimeFormatted()+" | "+G.getSignTimeFormatted()+" | "+G.getVerifyTimeFormatted()+" | "+G.getTotalTimeFormatted()+" | "+G.getRepeat()+" | "+G.isMatch()+" | "+G.isVerified());
      G = new Generator ("AES", "256", plainText, 100);  
      System.out.println(G.getAlgorithm()+"       | "+G.getKeySize()+"       | "+G.getKeyTimeFormatted()+" | "+G.getEncryptTimeFormatted()+" | "+G.getDecryptTimeFormatted()+" | "+G.getSignTimeFormatted()+" | "+G.getVerifyTimeFormatted()+" | "+G.getTotalTimeFormatted()+" | "+G.getRepeat()+" | "+G.isMatch()+" | "+G.isVerified());
      G = new Generator ("ECIES", "secp521r1", plainText, 10);  
      System.out.println(G.getAlgorithm()+"     | "+G.getKeySize()+" | "+G.getKeyTimeFormatted()+" | "+G.getEncryptTimeFormatted()+" | "+G.getDecryptTimeFormatted()+" | "+G.getSignTimeFormatted()+" | "+G.getVerifyTimeFormatted()+" | "+G.getTotalTimeFormatted()+" | "+G.getRepeat()+" | "+G.isMatch()+" | "+G.isVerified());
      G = new Generator ("T", "secp521r1", plainText, 10);  
      System.out.println(G.getAlgorithm()+"         | "+G.getKeySize()+" | "+G.getKeyTimeFormatted()+" | "+G.getEncryptTimeFormatted()+" | "+G.getDecryptTimeFormatted()+" | "+G.getSignTimeFormatted()+" | "+G.getVerifyTimeFormatted()+" | "+G.getTotalTimeFormatted()+" | "+G.getRepeat()+" | "+G.isMatch()+" | "+G.isVerified());
      System.out.println("");       
        
  }

}