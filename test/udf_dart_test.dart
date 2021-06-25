import 'dart:convert';

import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart';
import 'package:test/test.dart';
import 'package:udf_dart/udf_dart.dart';

void main() {
  group('UDFTest', () {
    test('Print base 32', () {
      var bytes = utf8.encode('I am francis here!');
      var presentationBase32 = UDF.printBase32(bytes, charsPerBlock: 4);
      var expected = 'JEQG-C3JA-MZZG-C3TD-NFZS-A2DF-OJSS-C';
      expect(presentationBase32, expected);
    });

    test('testUTF8BytesReadData', () {
      expect(hexPrintUtf8String('UDF Compressed Document 4187123'),
          '55 44 46 20 43 6F 6D 70 72 65 73 73 65 64 20 44 6F 63 75 6D 65 6E 74 20 34 31 38 37 31 32 33');
    });

    test('testUTF8BytesReadContentTypes hex print content type text/plain', () {
      expect(hexPrintUtf8String('text/plain'), '74 65 78 74 2F 70 6C 61 69 6E');
    });

    test('testSHA2Digest hex print sha512 of data H(<Data>)', () {
      var sha512Bytes = sha512.convert(utf8.encode('UDF Compressed Document 4187123')).bytes;
      const expected =
          '36 21 FA 2A C5 D8 62 5C 2D 0B 45 FB 65 93 FC 69 C1 ED F7 00 AE 6F E3 3D 38 13 FE AB 76 AA 74 13 6D 5A 2B 20 DE D6 A5 CF 6C 04 E6 56 3F F3 C0 C7 C4 1D 3F 43 DD DC F1 A5 67 A7 E0 67 9A B0 C6 B7';
      expect(hexPrintBytes(sha512Bytes), expected);
    });

    test('udfDataBufferTest hex print udf <Content-ID> + <:> + H(<Data>)', () {
      var dataDigest = sha512.convert(utf8.encode('UDF Compressed Document 4187123')).bytes;
      var udfDataBuffer = UDF.udfDataBuffer(dataDigest, 'text/plain');
      const expected =
          '74 65 78 74 2F 70 6C 61 69 6E 3A 36 21 FA 2A C5 D8 62 5C 2D 0B 45 FB 65 93 FC 69 C1 ED F7 00 AE 6F E3 3D 38 13 FE AB 76 AA 74 13 6D 5A 2B 20 DE D6 A5 CF 6C 04 E6 56 3F F3 C0 C7 C4 1D 3F 43 DD DC F1 A5 67 A7 E0 67 9A B0 C6 B7';
      expect(hexPrintBytes(udfDataBuffer), expected);
    });

    test('udfDataBufferTest2 H(<Content-ID> + <:> + H(<Data>))', () {
      var dataDigest = sha512.convert(utf8.encode('UDF Compressed Document 4187123')).bytes;
      var udfDataBuffer = UDF.udfDataBuffer(dataDigest, 'text/plain');
      var bufferDigest = sha512.convert(udfDataBuffer).bytes;
      const expected =
          '8E 14 D9 19 4E D6 02 12 C3 30 A7 BB 5F C7 17 6D AE 9A 56 7C A8 2A 23 1F 96 75 ED 53 10 EC E8 F2 60 14 24 D0 C8 BC 55 3D C0 70 F7 5E 86 38 1A 0B CB 55 9C B2 87 81 27 FF 3C EC E2 F0 90 A0 00 00';
      expect(hexPrintBytes(bufferDigest), expected);
    });

    test('udfBSDDataBufferTest2 testing compression, by', () {
      var dataDigest = sha512.convert(utf8.encode('UDF Compressed Document 4187123')).bytes;
      var udfDataBuffer = UDF.udfDataBuffer(dataDigest, 'text/plain');
      var bufferDigest = sha512.convert(udfDataBuffer).bytes;
      var compression = UDF.getCompression(bufferDigest);
      expect(compression, 1);

      var typeID = typeId(DigestAlgorithm.SHA2_512, compression);
      expect(typeID, UdfTypeIdentifier.Digest_SHA_2_512_20);

      var udfTypedBuffer = UDF.typeBDSToBinary(typeID, bufferDigest, precision: 800);
      const expected =
          '61 8E 14 D9 19 4E D6 02 12 C3 30 A7 BB 5F C7 17 6D AE 9A 56 7C A8 2A 23 1F 96 75 ED 53 10 EC E8 F2 60 14 24 D0 C8 BC 55 3D C0 70 F7 5E 86 38 1A 0B CB 55 9C B2 87 81 27 FF 3C EC E2 F0 90 A0 00';
      expect(hexPrintBytes(udfTypedBuffer), expected);
    });

    test('udfBSDDataBufferTest3', () {
      var udfTypedBuffer = UDF.dataToUDFBinary(utf8.encode('UDF Compressed Document 4187123'), 'text/plain', precision: 800);
      const expected =
          '61 8E 14 D9 19 4E D6 02 12 C3 30 A7 BB 5F C7 17 6D AE 9A 56 7C A8 2A 23 1F 96 75 ED 53 10 EC E8 F2 60 14 24 D0 C8 BC 55 3D C0 70 F7 5E 86 38 1A 0B CB 55 9C B2 87 81 27 FF 3C EC E2 F0 90 A0 00';
      expect(hexPrintBytes(udfTypedBuffer), expected);
    });

    test('udf800 printBase32 800 does use max precision 440.', () {
      var udfTypedBuffer = UDF.dataToUDFBinary(utf8.encode('UDF Compressed Document 4187123'), 'text/plain',
          precision: 800, digestAlgorithm: DigestAlgorithm.SHA2_512);
      // 440 bits
      const expectedFull =
          'MGHB-JWIZ-J3LA-EEWD-GCT3-WX6H-C5W2-5GSW-PSUC-UIY7-SZ26-2UYQ-5TUP-EYAU-ETIM-RPCV-HXAH-B526-QY4B-UC6L-KWOL-FB4B-E77T-Z3HC-6CIK-AAA';
      var presentationFull = UDF.printBase32(udfTypedBuffer, charsPerBlock: 4);
      expect(presentationFull, expectedFull);
    });

    test('udf125 printBase32 800 does use max precision 440.', () {
      var udfTypedBuffer = UDF.dataToUDFBinary(utf8.encode('UDF Compressed Document 4187123'), 'text/plain',
          precision: 200, digestAlgorithm: DigestAlgorithm.SHA2_512);

      const expectedShort = 'MGHB-JWIZ-J3LA-EEWD-GCT3-WX6H-C5W2';
      var presentationShort = UDF.printBase32(udfTypedBuffer, charsPerBlock: 4, precision: 125);
      expect(presentationShort, expectedShort);
    });

    test('testNonce', () {
      const nonceByte = 'CC 27 19 9C 4D C9 3B 71 EF 79 02 2E 5D 55 52 1B C3';
      var deleteWhitespace = nonceByte.replaceAll(RegExp(r'\s+'), '');
      var data = hex.decode(deleteWhitespace);
      var nonceBytes = UDF.nonce(data: data, bits: data.length * 8);
      var nonce = UDF.printBase32(nonceBytes, charsPerBlock: 4);
      var expected = 'NDGC-OGM4-JXET-W4PP-PEBC-4XKV-KINQ';
      expect(nonce, expected);
    });
  });

  group('AddressTest', () {
    test('testPhone125', () {
      var data = utf8.encode('+491722346123');
      var digest = UDF.dataToUDFBinary(data, 'phone');
      var udf5PerBlock = UDF.printBase32(digest, precision: 125);
      expect(udf5PerBlock, 'MCITH-W7U5A-KUJLL-F44ZK-QXF4Q');
      var udf4PerBlock = UDF.printBase32(digest, charsPerBlock: 4, precision: 125);
      expect(udf4PerBlock, 'MCIT-HW7U-5AKU-JLLF-44ZK-QXF4-QKHJ');
    });

    test('testEmail125', () {
      var data = utf8.encode('marion.mueller@mail.is');
      var digest = UDF.dataToUDFBinary(data, 'email');
      var udf5PerBlock = UDF.printBase32(digest, precision: 125);
      expect(udf5PerBlock, 'MDG3B-QLTSK-Y2DAR-3EIAH-2GI3L');
      var udf4PerBlock = UDF.printBase32(digest, charsPerBlock: 4, precision: 125);
      expect(udf4PerBlock, 'MDG3-BQLT-SKY2-DAR3-EIAH-2GI3-LZHZ');
    });

    test('testIban125', () {
      var data = utf8.encode('DE8937040044053201300');
      var digest = UDF.dataToUDFBinary(data, 'iban');
      var udf5PerBlock = UDF.printBase32(digest, precision: 125);
      expect(udf5PerBlock, 'MCDNU-FPD5R-6TGB3-RSP2K-X5RY3');
      var udf4PerBlock = UDF.printBase32(digest, charsPerBlock: 4, precision: 125);
      expect(udf4PerBlock, 'MCDN-UFPD-5R6T-GB3R-SP2K-X5RY-35UC');
    });

    test('testUUID', () {
      var uuid = 'b30eced7-4703-4995-b54c-25eef835ebca';
      var data = utf8.encode(uuid);
      var digest = UDF.dataToUDFBinary(data, 'uuid');
      var udf5PerBlock = UDF.printBase32(digest, precision: 125);
      expect(udf5PerBlock, 'MAYNJ-MUEGX-IX2ME-4SBLS-IMNAQ');
      var udf4PerBlock = UDF.printBase32(digest, charsPerBlock: 4, precision: 125);
      expect(udf4PerBlock, 'MAYN-JMUE-GXIX-2ME4-SBLS-IMNA-QEY6');
    });
  });
}

String hexPrintUtf8String(String input) {
  return hexPrintBytes(utf8.encode(input));
}

String hexPrintBytes(List<int> bytes) {
  var hexEncoded = hex.encode(bytes);
  return UDF.chunk(hexEncoded, 2).join(' ').toUpperCase();
}

enum AddressType { phone, email, iban }
