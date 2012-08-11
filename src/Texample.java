import java.security.SecureRandom;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECAlgorithms;
import java.math.BigInteger;
import java.security.*;


public class Texample {
  private int keySize;
  private SecureRandom random;
  private BigInteger priv;
  private ECPoint pub;
  private BigInteger n;
  private BigInteger p;
  private ECPoint G;
  private ECCurve curve;
  
  public Texample () throws Exception {   
    this.random = new SecureRandom();
  }
  
  public void establishKeys(String seccurve){
    ApprovedCurves c = new ApprovedCurves(seccurve);
    this.n = c.getN();
    this.p = c.getP();
    this.G = c.getG();
    this.curve = c.getCurve();
        
    // dA, dB are private
    // QA, QB are public
    BigInteger dB = new BigInteger (n.bitLength()-1, random).add(BigInteger.valueOf(1));
    ECPoint QB = G.multiply(dB);
    this.keySize = n.bitLength();
    this.priv = dB;
    this.pub = QB;  
  }

  public byte[] encrypt(byte[] plainText) throws Exception {

    BigInteger rA=BigInteger.valueOf(0);
    do{
      rA = new BigInteger (p.bitLength()-1, random);          
    }while(rA.equals(BigInteger.valueOf(0)));
    ECPoint RA = G.multiply(rA);
    
    // pad plaintext...
    int padBytes = ((int)Math.ceil((double)p.bitLength()/8)*2 - (plainText.length));
    byte[] paddedPlainText = new byte[plainText.length+padBytes+1];
    java.util.Arrays.fill(paddedPlainText, (byte)0x00);
    try {
      // encoding
      paddedPlainText[0] = (byte)(0x04);
      System.arraycopy(plainText, 0, paddedPlainText, paddedPlainText.length-plainText.length-1, plainText.length);
    } catch (Exception e) {
      System.err.println("Data must not be longer than "+((p.bitLength()*2)-1)/8+" bytes");
      throw e;
    }

    int x = padBytes;
    paddedPlainText[paddedPlainText.length-1] = (byte)((x & 0xff));

    ECPoint CM1 = RA;
    // (QB*rA) + pt
    ECPoint CM2 = (this.pub.multiply(rA).add(curve.decodePoint(paddedPlainText)));

    byte[] cipherText = new byte[CM1.getEncoded().length+CM2.getEncoded().length];
     
    System.arraycopy(CM1.getEncoded(), 0, cipherText, 0, CM1.getEncoded().length);
    System.arraycopy(CM2.getEncoded(), 0, cipherText, CM1.getEncoded().length, CM2.getEncoded().length);
    return cipherText;
  }
  
  public byte[] decrypt(byte[] cipherText) throws Exception {

    byte[] cipherText1 = new byte[cipherText.length/2];
    System.arraycopy(cipherText, 0, cipherText1, 0, cipherText.length/2);
    byte[] cipherText2 = new byte[cipherText.length/2];
    System.arraycopy(cipherText, cipherText.length/2, cipherText2, 0, cipherText.length/2);

    ECPoint CM1 = (curve.decodePoint(cipherText1));
    ECPoint CM2 = (curve.decodePoint(cipherText2));

    // pt = pt + (QB*rA) - RA*dB
    // QB*rA = RA*dB
    ECPoint Pm = CM2.subtract(CM1.multiply(this.priv));
    byte[] paddedDecryptedText = Pm.getEncoded();

    // strip decryptedtext
    // cut first byte specifying the encoding...
    byte[] decryptedText = new byte[paddedDecryptedText.length-1-(paddedDecryptedText[paddedDecryptedText.length-1] & 0xff)];
    System.arraycopy(paddedDecryptedText, paddedDecryptedText.length-decryptedText.length-1, decryptedText, 0, decryptedText.length);
    return decryptedText;
  }

  public byte[] sign(byte[] plainText) throws Exception {

    BigInteger rA=BigInteger.valueOf(0);
    do{
      rA = new BigInteger (p.bitLength()-1, random);          
    }while(rA.equals(BigInteger.valueOf(0)));
    ECPoint RA = G.multiply(rA);
    
    BigInteger r = RA.getX().toBigInteger().mod(n);
    
    MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
    messageDigest.update(plainText);
    BigInteger m = new BigInteger(messageDigest.digest());
    // (rA^-1)*(m+(priv*r))
    BigInteger s = ((rA.modInverse(n).multiply(m.add(priv.multiply(r)))));
    byte[] sbyte = s.toByteArray();
    byte[] rbyte = r.toByteArray();
    int maxlength;
    int roffset;
    int soffset;
    if (rbyte.length>sbyte.length){
      maxlength=rbyte.length;
      soffset=rbyte.length-sbyte.length;
      roffset=0;
      
    } else {
      maxlength=sbyte.length;
      roffset=sbyte.length-rbyte.length;
      soffset=0;
    }   
    byte[] signature = new byte[maxlength*2];
    System.arraycopy(rbyte,0,signature,roffset,maxlength-roffset);
    System.arraycopy(sbyte,0,signature,maxlength+soffset,maxlength-soffset);        
    return signature;       
  }
  
  public boolean verify(byte[] plainText, byte[] signature) throws Exception {

    MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
    messageDigest.update(plainText);
    BigInteger m = new BigInteger(messageDigest.digest());
    byte[] rbyte = new byte[signature.length/2];
    System.arraycopy(signature, 0, rbyte, 0, signature.length/2);
    byte[] sbyte = new byte[signature.length/2];
    System.arraycopy(signature, signature.length/2, sbyte, 0, signature.length/2);
    BigInteger r = new BigInteger(rbyte);
    BigInteger s = new BigInteger(sbyte);
    ECPoint rs = ECAlgorithms.sumOfTwoMultiplies(G, ((s.modInverse(n)).multiply(m)).mod(n), pub, ((s.modInverse(n)).multiply(r)).mod(n));
    BigInteger rp = rs.getX().toBigInteger().mod(n);
    return (rp.equals(r));
  }
  
  public int getKeySize() {
    return keySize;
  }

}
