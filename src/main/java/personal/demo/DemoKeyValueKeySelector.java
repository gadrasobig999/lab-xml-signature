package personal.demo;

import java.security.KeyException;
import java.security.PublicKey;
import java.util.List;
import java.util.Set;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyValue;

import lombok.NonNull;

public class DemoKeyValueKeySelector extends KeySelector {

  private final Set<String> DSA_SIGNATURES = Set.of(
      SignatureMethod.DSA_SHA1,
      SignatureMethod.DSA_SHA256);

  private final Set<String> RSA_SIGNATURES = Set.of(
      SignatureMethod.RSA_PSS,
      SignatureMethod.RSA_SHA1,
      SignatureMethod.RSA_SHA224,
      SignatureMethod.RSA_SHA256,
      SignatureMethod.RSA_SHA384,
      SignatureMethod.RSA_SHA512,
      SignatureMethod.SHA1_RSA_MGF1,
      SignatureMethod.SHA224_RSA_MGF1,
      SignatureMethod.SHA256_RSA_MGF1,
      SignatureMethod.SHA384_RSA_MGF1,
      SignatureMethod.SHA512_RSA_MGF1);

  @Override
  public KeySelectorResult select(@NonNull KeyInfo keyInfo, Purpose purpose, AlgorithmMethod method,
      XMLCryptoContext context)
      throws KeySelectorException {
    SignatureMethod sinatureMethod = (SignatureMethod) method;
    List<XMLStructure> listXmlStructures = keyInfo.getContent();

    for (XMLStructure xmlStructure : listXmlStructures) {
      if (xmlStructure instanceof KeyValue) {
        PublicKey publicKey = null;
        try {
          KeyValue keyValue = (KeyValue) xmlStructure;
          publicKey = keyValue.getPublicKey();
          compareAlgorithm(publicKey, sinatureMethod);
          return new DemoKeySelectorResult(publicKey);
        } catch (KeyException ke) {
          throw new KeySelectorException(ke);
        }
      }
    }
    throw new KeySelectorException("No KeyValue element found!");
  }

  protected void compareAlgorithm(@NonNull PublicKey publicKey, @NonNull AlgorithmMethod method)
      throws KeySelectorException {
    String fromKey = publicKey.getAlgorithm();
    String fromMethod = method.getAlgorithm();
    
    if (fromKey.equalsIgnoreCase("DSA") && DSA_SIGNATURES.stream().anyMatch(each -> each.equalsIgnoreCase(fromMethod))) {
      return;
    }
    if (fromKey.equalsIgnoreCase("RSA") && RSA_SIGNATURES.stream().anyMatch(each -> each.equalsIgnoreCase(fromMethod))) {
      return;
    }
    throw new KeySelectorException("Algorithm mismatched, key: " + fromKey + " ,method: " + method);

  }

}
