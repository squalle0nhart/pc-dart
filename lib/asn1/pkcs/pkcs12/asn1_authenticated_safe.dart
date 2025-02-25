import 'dart:typed_data';

import 'package:pointycastle/asn1.dart';

///
/// Taken from [RFC 7292](https://www.rfc-editor.org/rfc/rfc7292#page-10).
///```
/// AuthenticatedSafe ::= SEQUENCE OF ContentInfo
///```
///
class ASN1AuthenticatedSafe extends ASN1Object {

  ASN1AuthenticatedSafe();

  ASN1AuthenticatedSafe.fromSequence(ASN1Sequence seq) {
    if (seq.elements != null) {
      for (var element in seq.elements!) {
      }
    }
  }
}
