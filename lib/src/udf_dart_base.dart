library udf_dart;
// TODO: Put public facing types in this file.

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:base32/base32.dart';
import 'package:crypto/crypto.dart';

class UDFConstants {
  static const String udfEncryption = 'UDFEncryption';
  static const String pkixKey = 'PKIXKey';
}

enum DigestAlgorithm { SHA2_512, SHA3_512 }

enum UdfTypeIdentifier {
  /// Undefined type
  Unknown,

  /// Authenticator HMAC_SHA_2_512
  Authenticator_HMAC_SHA_2_512,

  /// Authenticator HMAC_SHA_3_512
  Authenticator_HMAC_SHA_3_512,

  /// Encryption HKDF_AES_512
  Encryption_HKDF_AES_512,

  /// EncryptionSignature HKDF_AES_512
  EncryptionSignature_HKDF_AES_512,

  /// Digest SHA_3_512
  Digest_SHA_3_512,

  /// Digest SHA_3_512 (20 bits compressed)
  Digest_SHA_3_512_20,

  /// Digest SHA_3_512 (30 bits compressed)
  Digest_SHA_3_512_30,

  /// Digest SHA_3_512 (40 bits compressed)
  Digest_SHA_3_512_40,

  /// Digest SHA_3_512 (50 bits compressed)
  Digest_SHA_3_512_50,

  /// Digest SHA_2_512
  Digest_SHA_2_512,

  /// Digest SHA_2_512 (20 bits compressed)
  Digest_SHA_2_512_20,

  /// Digest SHA_2_512 (30 bits compressed)
  Digest_SHA_2_512_30,

  /// Digest SHA_2_512 (40 bits compressed)
  Digest_SHA_2_512_40,

  /// Digest SHA_2_512 (50 bits compressed)
  Digest_SHA_2_512_50,

  /// Nonce Data
  Nonce,

  /// OID distinguished sequence (DER encoded)
  OID,

  /// Shamir Secret Share
  ShamirSecret,

  /// Secret seed
  DerivedKey
}

int idCode(UdfTypeIdentifier ti) {
  switch (ti) {
    case UdfTypeIdentifier.Unknown:
      return -1;
    case UdfTypeIdentifier.Authenticator_HMAC_SHA_2_512:
      return 0;
    case UdfTypeIdentifier.Authenticator_HMAC_SHA_3_512:
      return 1;
    case UdfTypeIdentifier.Encryption_HKDF_AES_512:
      return 32;
    case UdfTypeIdentifier.EncryptionSignature_HKDF_AES_512:
      return 33;
    case UdfTypeIdentifier.Digest_SHA_3_512:
      return 80;
    case UdfTypeIdentifier.Digest_SHA_3_512_20:
      return 81;
    case UdfTypeIdentifier.Digest_SHA_3_512_30:
      return 82;
    case UdfTypeIdentifier.Digest_SHA_3_512_40:
      return 83;
    case UdfTypeIdentifier.Digest_SHA_3_512_50:
      return 84;
    case UdfTypeIdentifier.Digest_SHA_2_512:
      return 96;
    case UdfTypeIdentifier.Digest_SHA_2_512_20:
      return 97;
    case UdfTypeIdentifier.Digest_SHA_2_512_30:
      return 98;
    case UdfTypeIdentifier.Digest_SHA_2_512_40:
      return 99;
    case UdfTypeIdentifier.Digest_SHA_2_512_50:
      return 100;
    case UdfTypeIdentifier.Nonce:
      return 104;
    case UdfTypeIdentifier.OID:
      return 112;
    case UdfTypeIdentifier.ShamirSecret:
      return 144;
    case UdfTypeIdentifier.DerivedKey:
      return 200;
    default:
      return -1;
  }
}

UdfTypeIdentifier typeId(DigestAlgorithm digestAlgorithm, int compression) {
  switch (digestAlgorithm) {
    case DigestAlgorithm.SHA2_512:
      switch (compression) {
        case 1:
          return UdfTypeIdentifier.Digest_SHA_2_512_20;
        case 2:
          return UdfTypeIdentifier.Digest_SHA_2_512_30;
        case 3:
          return UdfTypeIdentifier.Digest_SHA_2_512_40;
        case 4:
          return UdfTypeIdentifier.Digest_SHA_2_512_50;
        default:
          return UdfTypeIdentifier.Digest_SHA_2_512;
      }
      break;
    case DigestAlgorithm.SHA3_512:
      switch (compression) {
        case 1:
          return UdfTypeIdentifier.Digest_SHA_3_512_20;
        case 2:
          return UdfTypeIdentifier.Digest_SHA_3_512_30;
        case 3:
          return UdfTypeIdentifier.Digest_SHA_3_512_40;
        case 4:
          return UdfTypeIdentifier.Digest_SHA_3_512_50;
        default:
          return UdfTypeIdentifier.Digest_SHA_3_512;
      }
      break;
    default:
      throw ArgumentError(
          'Unexpected algorithm: ' + digestAlgorithm.toString());
  }
}

UdfTypeIdentifier idFromValue(int value) {
  return UdfTypeIdentifier.values.firstWhere((e) => idCode(e) == value,
      orElse: () => throw ArgumentError(
          'Unexpected UdfTypeIdentifier code: ' + value.toString()));
}

class UDF {
  /// Default number of UDF bits (usually 140)
  static const int defaultBits = 140;

  /// Minimum precision (usually 128)
  static const int minimumBits = 128;

  /// Maximum precision (usually 440)
  static const int maximumBits = 440;

  /// The tag separator.
  static final int tagSeparatorByte = ':'.codeUnits.first;

  // static final String defaultDelimiter = '-';

  // static final int defaultCharsPerBlock = 5;

  /// Convert a digest value and content type to a UDF buffer.
  ///
  /// [digest] Digest value to be formatted
  /// [contentType] MIME media type. See
  /// http://www.iana.org/assignments/media-types/media-types.xhtml for list.
  /// SHA2-512 (UTF8(ContentType) + ":" + SHA2512(Data))
  static List<int> udfBuffer(
      final List<int> dataDigest, final String contentType) {
    return sha512
        .newInstance()
        .convert(udfDataBuffer(dataDigest, contentType))
        .bytes;
  }

  /// Calculate a UDF fingerprint from the content data with specified precision.
  ///
  /// [contentType] MIME media type of data being fingerprinted.
  /// [data] Data to be fingerprinted.
  /// [precision] Precision, must be a multiple of 5bits * charsPerBlock.
  /// [cryptoAlgorithmId] The cryptographic digest to use to compute the hash value.
  /// [key] Optional key used to create a keyed fingerprint.
  /// Returns The binary UDF fingerprint.
  static List<int> dataToUDFBinary(List<int> data, String contentType,
      {int precision = 0,
      DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA2_512,
      String key}) {
    switch (digestAlgorithm) {
      case DigestAlgorithm.SHA2_512:
        // H(<Data>)
        var sha512Digest = sha512.newInstance().convert(data).bytes;
        // H(<Content-ID> + ':' + H(<Data>))
        return digestToUDFBinary(sha512Digest, contentType,
            precision: precision, digestAlgorithm: digestAlgorithm, key: key);
        break;
      case DigestAlgorithm.SHA3_512:
        throw ArgumentError('SHA3_512 not implemented');
      default:
        throw ArgumentError(
            'Unexpected algorithm: ' + digestAlgorithm.toString());
    }
  }

  /// Calculate a UDF fingerprint from the content digest with specified precision.
  ///
  /// [contentType] MIME media type of data being fingerprinted.
  /// [digest] Digest of the data to be fingerprinted.
  /// [bits] Precision, must be a multiple of 5bits * charsPerBlock.
  /// [cryptoAlgorithmId] The cryptographic digest to use to compute
  /// the hash value.
  /// [key] Optional key used to create a keyed fingerprint.
  /// Returns the binary UDF fingerprint
  static List<int> digestToUDFBinary(
      final List<int> digest, final String contentType,
      {int precision = 0,
      DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA2_512,
      String key}) {
    switch (digestAlgorithm) {
      case DigestAlgorithm.SHA2_512:
        // H(<Content-ID> + ':' + H(<Data>))
        return bufferDigestToUDF(udfBuffer(digest, contentType),
            precision: precision, digestAlgorithm: digestAlgorithm, key: key);
      case DigestAlgorithm.SHA3_512:
        throw ArgumentError('SHA3_512 not implemented');
      default:
        throw ArgumentError(
            'Unexpected algorithm: ' + digestAlgorithm.toString());
    }
  }

  /// Calculate a UDF fingerprint with specified precision.
  ///
  /// [buffer] The prepared data buffer.
  /// [bits] Precision, must be a multiple of 5bits * charsPerBlock.
  /// [cryptoAlgorithmId] The cryptographic digest to use to compute
  /// the hash value.
  /// [key] Key used to create a keyed fingerprint.
  /// @return The binary UDF fingerprint.
  static List<int> bufferDigestToUDF(List<int> digest,
      {int precision = 0,
      DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA2_512,
      String key}) {
    if (key == null) {
      // Data UDF
      var typeIdentifier = typeId(digestAlgorithm, getCompression(digest));
      return typeBDSToBinary(typeIdentifier, digest, precision: precision);
    } else {
      // Digest algorithm was applied in the costructor.
      switch (digestAlgorithm) {
        case DigestAlgorithm.SHA2_512:
          var udfData = Hmac(sha512, utf8.encode(key)).convert(digest).bytes;
          return typeBDSToBinary(
              UdfTypeIdentifier.Authenticator_HMAC_SHA_2_512, udfData,
              precision: precision);
        case DigestAlgorithm.SHA3_512:
          throw ArgumentError('SHA3_512 not implemented');
        default:
          throw ArgumentError(
              'Unexpected algorithm: ' + digestAlgorithm.toString());
      }
    }
  }

  /// Convert a Type Identifier and binary data sequence to a UDF binary buffer
  /// ready for presentation.
  ///
  /// [typeID] The type identifier.
  /// [source] The input buffer.
  /// [precision] The number of bits precision of the final output. If 0, the value
  /// of the property [defaultBits] is used.
  /// [offset] Offset in [source]
  /// Retuns the resulting binary buffer.
  static List<int> typeBDSToBinary(UdfTypeIdentifier typeID, List<int> source,
      {int precision = defaultBits, int offset = 0}) {
    // Constraints the number of bits to an integer multiple of 20 bits between
    // DefaultBits and MaximumBits.
    precision =
        min((precision <= 0 ? defaultBits : precision), source.length * 8);

    // Calculate the number of bytes
    var bytes = ((precision + 7) ~/ 8);

    var result = Uint8List(bytes);
    result.setAll(0, [idCode(typeID)]);
    List.copyRange(result, 1, source, 0, bytes - 1);
    return result;
  }

  /// Returns the compression level as determined by the number of trailing zero
  /// bits of buffer.
  ///
  /// @param digest The buffer to compress (MUST have at least 7 bytes)
  /// @return The compression level, 3 if there are 50 leading zeros, 2 if there
  ///         are 40 leading zeros, 1 if there are 20 and 0 otherwise.
  static int getCompression(List<int> digest) {
    // Uint8List buffer = digest;
    if (digest.length != 64) {
      throw ArgumentError('CryptographicException: wrong buffer length');
    }
    // Check for less than 20 trailing zeros
    var int_15 = int.parse('00001111', radix: 2);
    if ((digest[63] != 0) | (digest[62] != 0) | ((digest[61] & int_15) != 0)) {
      return 0;
    }

    // Check for less than 30 trailing zeros
    var int_63 = int.parse('00111111', radix: 2);
    if ((digest[61] != 0) | ((digest[60] & int_63) != 0)) {
      return 1;
    }

    // Check for less than 40 trailing zeros
    if ((digest[60] != 0) | (digest[59] != 0) | (digest[58] != 0)) {
      return 2;
    }

    // Check for less than 50 trailing zeros
    var int_3 = int.parse('00000011', radix: 2);
    if ((digest[57] != 0) | ((digest[56] & int_3) == 0)) {
      return 3;
    }
    return 4;
  }

  /// Print the base32 representation of the udf bytes.
  /// [udfBytes] the udf bytes
  /// [charsPerBlock] number of chars to be printed per block
  /// [delimiter] delimiter character
  /// [precision] the presision to be printed. Multiple of 5bits * [charsPerBlock]
  static String printBase32(List<int> udfBytes,
      {int charsPerBlock = 5, String delimiter = '-', int precision = -1}) {
    var encoded = base32.encode(udfBytes);
    var endIndex = encoded.indexOf('=');
    var base32String = endIndex > 0 ? encoded.substring(0, endIndex) : encoded;
    var blocks = chunk(base32String, charsPerBlock);

    // If bit is not specified, return the whole string.
    if (precision <= 0) return blocks.join(delimiter);

    // Else trim result to number of bits.

    // The number of blocks is dependent on the block size.
    // As each alphabet character can be represented using 5 bits,
    // each block has to have 5 * charsPerBlock
    var bytesPerBlock = 5 * charsPerBlock;
    var numberOfBloks = (precision + (bytesPerBlock - 1)) ~/ bytesPerBlock;
    numberOfBloks = min(numberOfBloks, blocks.length);
    return blocks.sublist(0, numberOfBloks).join(delimiter);
  }

  static List<String> chunk(String string, int charsPerBlock) {
    var chunks = <String>[];
    for (var start = 0; start < string.length; start += charsPerBlock) {
      chunks.add(
          string.substring(start, min(string.length, start + charsPerBlock)));
    }
    return chunks;
  }

  /// <Content-ID> + ':' + H(<Data>)
  ///
  /// [digest] the data digest H(<Data>)
  /// [contentType] the content type <Content-ID>
  /// return <Content-ID> + ':' + H(<Data>)
  static List<int> udfDataBuffer(
      final List<int> digest, final String contentType) {
    var resultBuffer = List<int>.from(utf8.encode(contentType));
    resultBuffer.add(tagSeparatorByte);
    resultBuffer.addAll(digest);
    return resultBuffer;
  }

  static List<int> nonceData(int bits) {
    var random = Random.secure();
    return List<int>.generate((bits - 8) ~/ 8, (i) => random.nextInt(256));
  }

  static List<int> nonce({List<int> data, int bits}) {
    bits ??= defaultBits;
    data ??= nonceData(bits);
    return typeBDSToBinary(UdfTypeIdentifier.Nonce, data, precision: bits);
  }

  /// Parse a UDF to obtain the type identifier and Binary Data Sequence.
  ///
  /// [udfString] UDF to parse.
  /// Returns the UDFBuffer
  static List<int> parse(String udfString) {
    return base32.decode(udfString);
  }

  static UdfTypeIdentifier typeIdFromDigest(Uint8List buffer) {
    return idFromValue(buffer.first);
  }

  static UdfTypeIdentifier typeIdFromUDF(String udfString) {
    var buffer = base32.decode(udfString);
    return typeIdFromDigest(buffer);
  }
}
