package personal.demo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.xml.security.c14n.Canonicalizer;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class LabVerifySignatureTest {

  @Test
  public void testVerifySignaureXmlOffered() throws Exception {
    byte[] toBeSigned = Files.readAllBytes(Paths.get("src/test/resources", "Canonicalized.xml"));
    byte[] xmlSignature = Files.readAllBytes(Paths.get("src/test/resources", "Signature.xml"));

    Signature signature = Signature.getInstance("SHA256withRSA");
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

    DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
    documentBuilderFactory.setValidating(false);
    documentBuilderFactory.setNamespaceAware(true);
    // documentBuilderFactory.setFeature("http://xml.org/sax/features/namespaces",
    // false);
    documentBuilderFactory.setFeature("http://xml.org/sax/features/validation", false);
    documentBuilderFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-dtd-grammar", false);
    documentBuilderFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
    Document document = documentBuilder.parse(new ByteArrayInputStream(xmlSignature));

    NodeList nodesX509Certificate = document.getElementsByTagName("X509Certificate");
    assertEquals(1, nodesX509Certificate.getLength());
    Node nodeX509Certificate = nodesX509Certificate.item(0);
    X509Certificate certificate = (X509Certificate) certificateFactory
        .generateCertificate(
            new ByteArrayInputStream(Base64.getMimeDecoder().decode(nodeX509Certificate.getTextContent())));

    NodeList nodesSignatureValue = document.getElementsByTagName("SignatureValue");
    assertEquals(1, nodesSignatureValue.getLength());
    Node nodeSignatureValue = nodesSignatureValue.item(0);
    byte[] signatureValue = Base64.getMimeDecoder().decode(nodeSignatureValue.getTextContent());

    signature.initVerify(certificate);
    signature.update(toBeSigned);
    boolean result = signature.verify(signatureValue);
    assertTrue(result);
  }

  @Test
  public void testVerifyCustomDemo() throws Exception {
    // byte[] toBeSigned = Files.readAllBytes(Paths.get("src/test/resources",
    // "Canonicalized.xml"));
    byte[] xmlSignature = Files.readAllBytes(Paths.get("src/test/resources", "ResultSigned.xml"));

    Signature signature = Signature.getInstance("SHA256withRSA");
    // CertificateFactory certificateFactory =
    // CertificateFactory.getInstance("X.509");

    DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
    documentBuilderFactory.setValidating(false);
    documentBuilderFactory.setNamespaceAware(true);
    // documentBuilderFactory.setFeature("http://xml.org/sax/features/namespaces",
    // false);
    documentBuilderFactory.setFeature("http://xml.org/sax/features/validation", false);
    documentBuilderFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-dtd-grammar", false);
    documentBuilderFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
    Document document = documentBuilder.parse(new ByteArrayInputStream(xmlSignature));

    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(
        Base64.getDecoder().decode(Files.readAllBytes(Paths.get("src/test/resources", "publickey.txt"))));
    RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpecX509);

    NodeList nodesSignatureValue = document.getElementsByTagName("SignatureValue");
    assertEquals(1, nodesSignatureValue.getLength());
    Node nodeSignatureValue = nodesSignatureValue.item(0);
    byte[] signatureValue = Base64.getMimeDecoder().decode(nodeSignatureValue.getTextContent());
    // System.out.println(Base64.getEncoder().encodeToString(signatureValue));

    NodeList nodesToBeSigned = document.getElementsByTagName("SignedInfo");
    assertEquals(1, nodesToBeSigned.getLength());
    Node nodeToBeSigned = nodesToBeSigned.item(0);

    ByteArrayOutputStream canonicalized = new ByteArrayOutputStream();
    org.apache.xml.security.Init.init();
    Canonicalizer canonicalizer = Canonicalizer.getInstance(CanonicalizationMethod.INCLUSIVE);
    canonicalizer.canonicalizeSubtree(nodeToBeSigned, canonicalized);
    // System.out.println(new String(canonicalized.toByteArray()));

    signature.initVerify(publicKey);
    signature.update(canonicalized.toByteArray());
    boolean result = signature.verify(signatureValue);
    assertTrue(result);
  }

  @Test
  public void testVerifySignaureXmlOffered2() throws Exception {
    // byte[] toBeSigned = Files.readAllBytes(Paths.get("src/test/resources",
    // "Canonicalized.xml"));
    byte[] xmlSignature = Files.readAllBytes(Paths.get("src/test/resources", "Signature.xml"));

    Signature signature = Signature.getInstance("SHA256withRSA");
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

    DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
    documentBuilderFactory.setValidating(false);
    documentBuilderFactory.setNamespaceAware(true);
    // documentBuilderFactory.setFeature("http://xml.org/sax/features/namespaces",
    // false);
    documentBuilderFactory.setFeature("http://xml.org/sax/features/validation", false);
    documentBuilderFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-dtd-grammar", false);
    documentBuilderFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
    Document document = documentBuilder.parse(new ByteArrayInputStream(xmlSignature));

    NodeList nodesX509Certificate = document.getElementsByTagName("X509Certificate");
    assertEquals(1, nodesX509Certificate.getLength());
    Node nodeX509Certificate = nodesX509Certificate.item(0);
    X509Certificate certificate = (X509Certificate) certificateFactory
        .generateCertificate(
            new ByteArrayInputStream(Base64.getMimeDecoder().decode(nodeX509Certificate.getTextContent())));

    NodeList nodesSignatureValue = document.getElementsByTagName("SignatureValue");
    assertEquals(1, nodesSignatureValue.getLength());
    Node nodeSignatureValue = nodesSignatureValue.item(0);
    byte[] signatureValue = Base64.getMimeDecoder().decode(nodeSignatureValue.getTextContent());

    NodeList nodesToBeSigned = document.getElementsByTagName("SignedInfo");
    assertEquals(1, nodesToBeSigned.getLength());
    Node nodeToBeSigned = nodesToBeSigned.item(0);

    ByteArrayOutputStream canonicalized = new ByteArrayOutputStream();
    org.apache.xml.security.Init.init();
    Canonicalizer canonicalizer = Canonicalizer.getInstance(CanonicalizationMethod.INCLUSIVE);
    canonicalizer.canonicalizeSubtree(nodeToBeSigned, canonicalized);

    signature.initVerify(certificate);
    signature.update(canonicalized.toByteArray());
    boolean result = signature.verify(signatureValue);
    assertTrue(result);
  }

  @Test
  public void verifyCardServer() throws Exception {
    String cerb64 = "MIIE+zCCA+OgAwIBAgIQQwXZFhCARlzzQPBJ6mzHJjANBgkqhkiG9w0BAQsFADBWMQswCQYDVQQGEwJUVzESMBAGA1UECgwJ6KGM5pS/6ZmiMTMwMQYDVQQLDCoo5ris6Kmm55SoKSDmlL/lupzmuKzoqabmhpHorYnnrqHnkIbkuK3lv4MwHhcNMjMwODIzMDMwMjM3WhcNMjQwMjIzMDMwMjM3WjA4MQswCQYDVQQGEwJUVzEWMBQGA1UECgwN5ris6Kmm5YWs5Y+4MTERMA8GA1UEBRMIODI2NzUxMzIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8TWAICkZ2tIFhRO+fxGRNiUkZTpL69Y+XNQ/2ei0sbRba9FRNmdTtKi+0MC4cn9qIseFfhRP+oQBkfWAKFNtZHoEYHQEep+MHZfU24ex2CdzKjAWyu9xupmnz65ypCV/FQKd8l+kJuF/xBeTpoQcjP8rHCD8DNEG0Jf2nkk5cdnym/ND0dJQSliDbNUrBBKSvV0zcW3jpbu5f+y5wD46EwymZ2qXohXqxb0D2H9jP1lsbTnU+Wo87oOhy4BTSU2KEUPqQfeeZ1l3jsvWIB6/CzpPOf3dUPHGq3Vs+Fh2yEIW2Yi8ckZqqJsRnrzqMgfuVHlZMOE8k9kOsPYWi6hctAgMBAAGjggHhMIIB3TAfBgNVHSMEGDAWgBR3r9Blh+4dyKn2l6AlRw7JldpxqzAdBgNVHQ4EFgQUysGuGzYXymAGkfAOKnYRn8yoROMwDgYDVR0PAQH/BAQDAgeAMBQGA1UdIAQNMAswCQYHYIZ2ZQADADAaBgNVHREEEzARgQ90ZXN0QGNodC5jb20udHcwTwYDVR0JBEgwRjAXBgdghnYBZAIBMQwGCmCGdgFkAwICAQEwFAYHYIZ2AWQCAjEJEwdwcmltYXJ5MBUGB2CGdgFkAmUxCgwIODI2NzUxMzIwgYYGA1UdHwR/MH0wQKA+oDyGOmh0dHA6Ly9ndGVzdGNhLm5hdC5nb3YudHcvY3JsL0dUZXN0Q0EyLzg4ODgtMS9jb21wbGV0ZS5jcmwwOaA3oDWGM2h0dHA6Ly9ndGVzdGNhLm5hdC5nb3YudHcvY3JsL0dUZXN0Q0EyL2NvbXBsZXRlLmNybDB/BggrBgEFBQcBAQRzMHEwPgYIKwYBBQUHMAKGMmh0dHA6Ly9ndGVzdGNhLm5hdC5nb3YudHcvY2VydHMvSXNzdWVkVG9UaGlzQ0EucDdiMC8GCCsGAQUFBzABhiNodHRwOi8vZ3Rlc3RjYS5uYXQuZ292LnR3L09DU1Avb2NzcDANBgkqhkiG9w0BAQsFAAOCAQEAMZ00cn0AeX9/Tyq/a+SAM8G0IPNTGn0YSfuIwz/YISIW0o/eYmSFRekP42St9JZIyt9Psp//ozgZKCL8KgDZkV2trFU6+XXnMX71jaUOdw15snQWOifDp7pq8931QRaJKXxSwPWDrrGwgwLEMpJfnwEknc3RFQW7n/YLxPNpjc+ufGX/+LAAzHlnbNB+Qurems06lJIU9aZrhrowK5Zr37HRak3Npuq6lID3zCxCoE5cl4ylPD/FZPQ0rUnzxxnqtJMmE0MeUpDtKARmjvYmRfaUH8KHnzF68pNFr5OH1b5n0NTGwu9tcK0skYMOzXWnvIlt10a4cOYd0+8NezKIdg==";
    String signed = "TwTN8ye3nOzfRlw7mpfUMXrU3wbKv2ZzDj2swta68w//RcPvcerBBut0M2b3+awSfqMh01S26OapNVB+gP9Tt1irmymOInEBcAeh5pnO/hjtn3ozt0BNKlRVSX/o6AuMacW41aoQWf3+6982TTKQzhTbGN3+7YYjINVy6+y5yLjubG983WPs5XD4qnO3EAio1dgaDOVYIGbEag8p8T5WOvgwnE7c1ssRKzEshzDKWH0iGp2NAA0FGd8BpxRhp6a0Qn48BkOaPt5VhYBaoZDKikJ6Gz0iBno36TrE+qRo6tSa9oGK3pU49y6Qw74WZ0kpYCMsBtzmNqdsLeSOdzTUPA==";
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    X509Certificate certificate = (X509Certificate) certificateFactory
        .generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(cerb64)));
    Signature signature = Signature.getInstance("SHA256withRSA");
    signature.initVerify(certificate);
    signature.update(Files.readAllBytes(Paths.get("src/test/resources", "correct_canonicalized.xml")));
    boolean result = signature.verify(Base64.getDecoder().decode(signed));
    assertTrue(result);
  }

}
