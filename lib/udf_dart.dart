/// This module implement UDF such as defined in [Mathematical Mesh 3.0 Part II: Uniform Data Fingerprint draft-hallambaker-mesh-udf-11](https://www.ietf.org/archive/id/draft-hallambaker-mesh-udf-11.txt).
///
/// Give a piece of data DATA.
/// - The UDF is defined as: ```H(<Content-ID> + ':' + H(<Data>))``` where H is the hash algerithm used to compute the digest of data presented. The Content-ID is the mime type of DATA (or any meta infor used qo qualify DATA).
/// - In the final representation, the UDF is prefixed by a byindicating the UDFTypeIdentifier as defined in [mmesh-3.2](https://tools.ietf.org/html/draft-hallambaker-mesh-udf-10#section-3.2)

/// More dartdocs go here.
library udf_dart;

export 'src/udf_dart_base.dart';

// TODO: Export any libraries intended for clients of this package.
