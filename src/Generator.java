import java.text.DecimalFormat;

public class Generator {
  private double totalTime;
  private double keyTime; 
  private double encryptTime;
  private double decryptTime;
  private double signTime;
  private double verifyTime;
  private String keySize;
  private boolean match;
  private boolean verified;
  private String algorithm;
  private double repeat;
  
  public Generator (String alg, String keysize, byte[] plainText, double repeat) throws Exception { 

    this.algorithm=alg;
    double ktime = 0;
    double etime = 0;
    double dtime = 0;
    double stime = 0;
    double vtime = 0;
    double delta = 0;
    this.match=true;
    this.verified=true;
    this.repeat = repeat;
    double DIV = 1000000000;
  
    if (alg == "RSA"){
      for (int i=0; i<repeat; i++){
          RSAexample Test = new RSAexample();
          
          delta = System.nanoTime();
          Test.establishKeys(keysize);
          delta = (System.nanoTime() - delta)/DIV;
          ktime += delta;
          
          delta = System.nanoTime();
          byte[] cipherText = Test.encrypt(plainText);
          delta = (System.nanoTime() - delta)/DIV;
          etime += delta;

          delta = System.nanoTime();
          byte[] decryptedText = Test.decrypt(cipherText);
          delta = (System.nanoTime() - delta)/DIV;
          dtime += delta;

          delta = System.nanoTime();
          byte[] signature = Test.sign(plainText);
          delta = (System.nanoTime() - delta)/DIV;
          stime += delta;
          
          delta = System.nanoTime();
          if ( !(Test.verify(plainText,signature)) ){
            this.verified=false;
          }
          
          delta = (System.nanoTime() - delta)/DIV;
          vtime += delta;
          
        if (!(java.util.Arrays.equals(plainText, decryptedText))){
          this.match=false;
        }
      }
      
    } else if (alg == "ECIES"){
      for (int i=0; i<repeat; i++){
          ECIESexample Test = new ECIESexample();
          
          delta = System.nanoTime();
          Test.establishKeys(keysize);
          delta = (System.nanoTime() - delta)/DIV;
          ktime += delta;
          
          delta = System.nanoTime();
          byte[] cipherText = Test.encrypt(plainText);
          delta = (System.nanoTime() - delta)/DIV;
          etime += delta;

          delta = System.nanoTime();
          byte[] decryptedText = Test.decrypt(cipherText);
          delta = (System.nanoTime() - delta)/DIV;
          dtime += delta;
          
          delta = System.nanoTime();
          byte[] signature = Test.sign(plainText);
          delta = (System.nanoTime() - delta)/DIV;
          stime += delta;
          
          delta = System.nanoTime();
          if ( !(Test.verify(plainText,signature)) ){
            this.verified=false;
          }
          
          delta = (System.nanoTime() - delta)/DIV;
          vtime += delta;
          
        if (!(java.util.Arrays.equals(plainText, decryptedText))){
          this.match=false;
        }
      }
      
    } else if (alg == "AES"){
      for (int i=0; i<repeat; i++){
          AESexample Test = new AESexample();
          
          delta = System.nanoTime();
          Test.establishKeys(keysize);
          delta = (System.nanoTime() - delta)/DIV;
          ktime += delta;
          
          delta = System.nanoTime();
          byte[] cipherText = Test.encrypt(plainText);
          delta = (System.nanoTime() - delta)/DIV;
          etime += delta;

          delta = System.nanoTime();
          byte[] decryptedText = Test.decrypt(cipherText);
          delta = (System.nanoTime() - delta)/DIV;
          dtime += delta;
          
          this.verified=false;
          stime=0;
          vtime=0;
                            
        if (!(java.util.Arrays.equals(plainText, decryptedText))){
          this.match=false;
        }
      }
    } else if (alg == "T"){
      for (int i=0; i<repeat; i++){
          Texample Test = new Texample();
          
          delta = System.nanoTime();
          Test.establishKeys(keysize);
          delta = (System.nanoTime() - delta)/DIV;
          ktime += delta;
          
          delta = System.nanoTime();
          byte[] cipherText = Test.encrypt(plainText);
          delta = (System.nanoTime() - delta)/DIV;
          etime += delta;

          delta = System.nanoTime();
          byte[] decryptedText = Test.decrypt(cipherText);
          delta = (System.nanoTime() - delta)/DIV;
          dtime += delta;
          
          delta = System.nanoTime();
          byte[] signature = Test.sign(plainText);
          delta = (System.nanoTime() - delta)/DIV;
          stime += delta;
          
          delta = System.nanoTime();
          if ( !(Test.verify(plainText,signature)) ){
            this.verified=false;
          }
          
          delta = (System.nanoTime() - delta)/DIV;
          vtime += delta;
          
        if (!(java.util.Arrays.equals(plainText, decryptedText))){
          this.match=false;
        }
      } 
    } else {
      this.keySize = "";
      this.match = false;
      this.verified = false;
      this.algorithm = "NONE";  
    }
    this.totalTime = (ktime + etime + dtime + stime + vtime)/repeat;
    this.keyTime = ktime/repeat;
    this.encryptTime = etime/repeat;
    this.decryptTime = dtime/repeat;
    this.signTime = stime/repeat;
    this.verifyTime = vtime/repeat;
    this.keySize = keysize;
    
  }

  public String getTotalTimeFormatted() {
    DecimalFormat f = new DecimalFormat("#.#########");
    return f.format(totalTime);
  }
  
  public double getTotalTime() {
    return totalTime;
  }

  public String getKeyTimeFormatted() {
    DecimalFormat f = new DecimalFormat("#.#########");
    return f.format(keyTime);
  }

  public double getKeyTime() {
    return keyTime;
  }
  
  public String getEncryptTimeFormatted() {
    DecimalFormat f = new DecimalFormat("#.#########");
    return f.format(encryptTime);
  }
  
  public double getEncryptTime() {
    return encryptTime;
  }

  public String getDecryptTimeFormatted() {
    DecimalFormat f = new DecimalFormat("#.#########");
    return f.format(decryptTime);
  }
  public double getDecryptTime() {
    return decryptTime;
  }

  public String getSignTimeFormatted() {
    DecimalFormat f = new DecimalFormat("#.#########");
    return f.format(signTime);
  }
  
  public double getSignTime() {
    return signTime;
  }

  public String getVerifyTimeFormatted() {
    DecimalFormat f = new DecimalFormat("#.#########");
    return f.format(verifyTime);
  }
  
  public double getVerifyTime() {
    return verifyTime;
  }
  
  public String getKeySize() {
    return keySize;
  }
  
  public double getRepeat() {
    return repeat;
  }

  public boolean isMatch() {
    return match;
  }

  public boolean isVerified() {
    return verified;
  }
  
  public String getAlgorithm() {
    return algorithm;
  }
}
