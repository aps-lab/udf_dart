This module implement UDF such as defined in [Mathematical Mesh 3.0 Part II: Uniform Data Fingerprint draft-hallambaker-mesh-udf-11](https://www.ietf.org/archive/id/draft-hallambaker-mesh-udf-11.txt).

Give a piece of data DATA.
- The UDF is defined as: ```H(<Content-ID> + ':' + H(<Data>))``` where H is the hash algerithm used to compute the digest of data presented. The Content-ID is the mime type of DATA (or any meta infor used qo qualify DATA).
- In the final representation, the UDF is prefixed by a byindicating the UDFTypeIdentifier as defined in [mmesh-3.2](https://tools.ietf.org/html/draft-hallambaker-mesh-udf-11#section-3.2)

Created from templates made available by Stagehand under a BSD-style
[license](https://github.com/dart-lang/stagehand/blob/master/LICENSE).

## Usage

A simple usage example:

```dart
import 'dart:convert';

import 'package:udf_dart/udf_dart.dart';

void main() {
  var digest = UDF.dataToUDFBinary(utf8.encode('+491722346123'), 'phone');
  var udf5PerBlock = UDF.printBase32(digest, precision: 125);
  print('UDF of +491722346123 is : ${udf5PerBlock}');
}
```

## Features and bugs

Please file feature requests and bugs at the [issue tracker][tracker].

[tracker]: https://github.com/aps-lab/udf_dart/issues
