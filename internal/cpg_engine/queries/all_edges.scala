cpg.call
  .flatMap(call => call.callee.map(callee =>
    s"""{
      "from":  "${call.method.id.toString}",
      "to":    "${callee.id.toString}",
      "type":  "CALL",
      "label": ""
    }"""
  ))
  .toList
  .mkString("[", ",", "]")