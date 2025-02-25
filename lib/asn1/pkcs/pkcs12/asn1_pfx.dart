import 'dart:typed_data';

import 'package:pointycastle/asn1.dart';

///
///```
/// PFX ::= SEQUENCE {
///   version     INTEGER {v3(3)}(v3,...),
///   authSafe    ContentInfo,
///   macData     MacData OPTIONAL
/// }
///```
///
class ASN1Pfx extends ASN1Object {
  late ASN1Integer version;
  ASN1MacData? macData;

  ASN1Pfx(this.version, {this.macData});

  ///
  /// Creates an instance of [PFX] from the given [sequence]. The sequence must have at least 2 elements.
  ///
  ASN1Pfx.fromSequence(ASN1Sequence seq) {
    if (seq.elements == null || seq.elements!.isEmpty) {
      throw ArgumentError('Empty sequence');
    }
    if (seq.elements!.length == 1) {
      throw ArgumentError('Sequence has not enough elements');
    }
    version = seq.elements!.elementAt(0) as ASN1Integer;
    if (version.integer!.toInt() != 3) {
      throw ArgumentError('Wrong version for PFX PDU');
    }
    if (seq.elements!.length == 3) {
      macData =
          ASN1MacData.fromSequence(seq.elements!.elementAt(2) as ASN1Sequence);
    }
  }

  @override
  Uint8List encode(
      {ASN1EncodingRule encodingRule = ASN1EncodingRule.ENCODING_DER}) {
    var tmp = ASN1Sequence(elements: [version]);
    if (macData != null) {
      tmp.add(macData!);
    }
    return tmp.encode(encodingRule: encodingRule);
  }
}
