import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import java.math.BigInteger;

public class ApprovedCurves {
  private BigInteger p;
  private BigInteger a;
  private BigInteger b;
  private BigInteger n;
  private BigInteger h;
  private ECCurve curve;
  private ECPoint G;
  
  public ApprovedCurves(String named) {

    // SEC equiv RSA 1024 (80 bit)
    if(named == "secp160r1"){
      this.p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF", 16);
      this.a = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC", 16);
      this.b = new BigInteger("1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45", 16);
      this.n = new BigInteger("0100000000000000000001F4C8F927AED3CA752257", 16);
      this.h = BigInteger.valueOf(1);
      this.curve = new ECCurve.Fp(p, a, b);
      this.G = curve.decodePoint(new BigInteger("04"
          + "4A96B5688EF573284664698968C38BB913CBFC82"
          + "23A628553168947D59DCC912042351377AC5FB32", 16).toByteArray());
    
    // SEC equiv RSA 2048 (112 bit)
    } else if(named == "secp224r1"){
      this.p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001", 16);
      this.a = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE", 16);
      this.b = new BigInteger("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4", 16);
      this.n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D", 16);
      this.h = BigInteger.valueOf(1);
      this.curve = new ECCurve.Fp(p, a, b);
      this.G = curve.decodePoint(new BigInteger("04"
                  + "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21"
                  + "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34", 16).toByteArray());

    // SEC equiv RSA 7680 (192 bit)
    } else if(named == "secp384r1"){
      this.p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", 16);
      this.a = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC", 16);
      this.b = new BigInteger("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF", 16);
      this.n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", 16);
      this.h = BigInteger.valueOf(1);
      this.curve = new ECCurve.Fp(p, a, b);
      this.G = curve.decodePoint(new BigInteger("04"
                  + "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"
                  + "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F", 16).toByteArray()); 

    // SEC equiv RSA 15360 (256 bit)
    } else if(named == "secp521r1"){
      this.p = new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);
      this.a = new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC", 16);
      this.b = new BigInteger("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00", 16);
      this.n = new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", 16);
      this.h = BigInteger.valueOf(1);
      this.curve = new ECCurve.Fp(p, a, b);
      this.G = curve.decodePoint(new BigInteger("04"
                  + "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66"
                  + "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650", 16).toByteArray());   

    // Koblitz equiv RSA 1024 (80 bit)
    } else if(named == "secp160k1"){
      this.p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73", 16);
      this.a = BigInteger.valueOf(0);
      this.b = BigInteger.valueOf(7);
      this.n = new BigInteger("0100000000000000000001B8FA16DFAB9ACA16B6B3", 16);
      this.h = BigInteger.valueOf(1);
      this.curve = new ECCurve.Fp(p, a, b);
      this.G = curve.decodePoint(new BigInteger("04"
                + "3B4C382CE37AA192A4019E763036F4F5DD4D7EBB"
                + "938CF935318FDCED6BC28286531733C3F03C4FEE", 16).toByteArray());
      
    // Koblitz equiv RSA 2048 (112 bit)
    } else if(named == "secp224k1"){
      this.p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D", 16);
      this.a = BigInteger.valueOf(0);
      this.b = BigInteger.valueOf(5);
      this.n = new BigInteger("010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7", 16);
      this.h = BigInteger.valueOf(1);
      this.curve = new ECCurve.Fp(p, a, b);
      this.G = curve.decodePoint(new BigInteger("04"
                  + "A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C"
                  + "7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5", 16).toByteArray());
    }
    
  }

  public BigInteger getP() {
    return p;
  }

  public BigInteger getA() {
    return a;
  }

  public BigInteger getB() {
    return b;
  }

  public BigInteger getN() {
    return n;
  }

  public BigInteger getH() {
    return h;
  }

  public ECCurve getCurve() {
    return curve;
  }

  public ECPoint getG() {
    return G;
  }
}