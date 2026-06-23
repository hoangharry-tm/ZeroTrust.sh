@GetMapping("/documents/{docId}")
public ResponseEntity<Document> getDocument(@PathVariable String docId) {
    Document doc = documentRepository.findById(docId).orElseThrow();
    return ResponseEntity.ok(doc);
}
