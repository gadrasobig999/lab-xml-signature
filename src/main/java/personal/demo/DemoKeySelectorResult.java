package personal.demo;

import java.security.Key;

import javax.xml.crypto.KeySelectorResult;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class DemoKeySelectorResult implements KeySelectorResult {

  @Getter
  private final Key key;

}
