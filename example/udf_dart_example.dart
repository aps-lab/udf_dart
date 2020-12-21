import 'dart:convert';

import 'package:udf_dart/udf_dart.dart';

void main() {
  var digest = UDF.dataToUDFBinary(utf8.encode('+491722346123'), 'phone');
  var udf5PerBlock = UDF.printBase32(digest, precision: 125);
  print('UDF of +491722346123 is : ${udf5PerBlock}');
}
