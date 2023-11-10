package personal.demo;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

@SpringBootTest(webEnvironment = WebEnvironment.DEFINED_PORT)
public class LabCreateAndValidateXMLSignatureTest {
  
  @LocalServerPort
	private Integer port;

	private final Path TEST_RESOURCES = Paths.get("src/test/resources");
	private final Path PUBLICKEY = TEST_RESOURCES.resolve("publickey.txt");
	private final Path PRIVATEKEY = TEST_RESOURCES.resolve("privatekey.txt");
	private final Path GENEREATED = TEST_RESOURCES.resolve("ResultSigned.xml");

	final URI getFoo() {
		return URI.create("http://localhost:" + port + "/foo.txt");
	};

	final URI getBar() {
		return URI.create("http://localhost:" + port + "/bar.txt");
	};

	public void generateRSAKeyPairFiles() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		Files.write(PRIVATEKEY, Base64.getEncoder().encode(privateKey.getEncoded()),
				StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.CREATE);
		Files.write(PUBLICKEY, Base64.getEncoder().encode(publicKey.getEncoded()),
				StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.CREATE);
	}

	public void createXMLSignatureFile() throws Exception {
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(
				Base64.getDecoder().decode(Files.readAllBytes(PRIVATEKEY)));
		X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(Files.readAllBytes(PUBLICKEY)));
		RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(keySpecPKCS8);
		RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpecX509);

		XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance();
		CanonicalizationMethod canonicalizationMethod = xmlSignatureFactory
				.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null);
		SignatureMethod signatureMethod = xmlSignatureFactory.newSignatureMethod(SignatureMethod.RSA_SHA256, null);
		Reference reference0 = xmlSignatureFactory.newReference(getFoo().toString(),
				xmlSignatureFactory.newDigestMethod(DigestMethod.SHA256, null));
		Reference reference1 = xmlSignatureFactory.newReference(getBar().toString(),
				xmlSignatureFactory.newDigestMethod(DigestMethod.SHA256, null));
		SignedInfo signedInfo = xmlSignatureFactory.newSignedInfo(canonicalizationMethod, signatureMethod,
				List.of(reference0, reference1));
		KeyInfoFactory keyInfoFactory = xmlSignatureFactory.getKeyInfoFactory();
		KeyValue keyValue = keyInfoFactory.newKeyValue(publicKey);
		KeyInfo keyInfo = keyInfoFactory.newKeyInfo(List.of(keyValue));

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		Document document = dbf.newDocumentBuilder().newDocument();
		Element helloWorld = document.createElement("HelloWorld");
		Element whatever = document.createElement("Whatever");
		whatever.setTextContent("This is a simple demo");
		helloWorld.appendChild(whatever);
		document.appendChild(helloWorld);

		DOMSignContext dsc = new DOMSignContext(privateKey, document.getDocumentElement());
		XMLSignature signature = xmlSignatureFactory.newXMLSignature(signedInfo, keyInfo);
		signature.sign(dsc);

		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer trans = tf.newTransformer();
		ByteArrayOutputStream targetOutputStream = new ByteArrayOutputStream();
		trans.transform(new DOMSource(document), new StreamResult(targetOutputStream));

		Files.write(GENEREATED, targetOutputStream.toByteArray(), StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.CREATE);
	}

	public void validateCreatedXMLSignatureFile() throws Exception {
		ByteArrayInputStream sourceInputStream = new ByteArrayInputStream(Files.readAllBytes(GENEREATED));
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		Document doc = documentBuilderFactory.newDocumentBuilder().parse(sourceInputStream);
		NodeList signatureList = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
		DOMValidateContext domValidateContext = new DOMValidateContext(new DemoKeyValueKeySelector(),
				signatureList.item(0));
		domValidateContext.setProperty("org.jcp.xml.dsig.secureValidation", false); // turn off http check
		XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance();
		XMLSignature xmlSignature = xmlSignatureFactory.unmarshalXMLSignature(domValidateContext);
		boolean isValid = xmlSignature.validate(domValidateContext);
		assertTrue(isValid);
	}

	@Test
	void test_createNewXMLSignatureAndValidate() throws Exception {
		createXMLSignatureFile();
		validateCreatedXMLSignatureFile();
	}

}
