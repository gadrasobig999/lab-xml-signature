package personal.demo;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

public class LabReadOfferedXMLSignatureTest {

  private final Path TEST_RESOURCES = Paths.get("src/test/resources");
  private final Path SIGNATURE_EXAMPLE = TEST_RESOURCES.resolve("Signature.xml");

  @Test
  void test_validateOfferedExample() throws Exception {
    ByteArrayInputStream sourceInputStream = new ByteArrayInputStream(Files.readAllBytes(SIGNATURE_EXAMPLE));
    DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
    documentBuilderFactory.setNamespaceAware(true);
    Document doc = documentBuilderFactory.newDocumentBuilder().parse(sourceInputStream);
    NodeList signatureList = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    DOMValidateContext domValidateContext = new DOMValidateContext(new DemoKeyValueKeySelector(),
        signatureList.item(0));
    domValidateContext.setProperty("org.jcp.xml.dsig.secureValidation", false);
    XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance();
    XMLSignature xmlSignature = xmlSignatureFactory.unmarshalXMLSignature(domValidateContext);
    boolean isValid = xmlSignature.validate(domValidateContext);
    assertTrue(isValid);
  }

}
