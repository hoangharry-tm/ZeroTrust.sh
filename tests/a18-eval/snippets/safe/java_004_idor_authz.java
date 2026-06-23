@GetMapping("/documents/{docId}")
public ResponseEntity<Document> getDocument(
        @PathVariable String docId,
        @AuthenticationPrincipal UserDetails user) {
    Document doc = documentRepository.findById(docId).orElseThrow();
    if (!doc.getOwnerUsername().equals(user.getUsername())) {
        throw new AccessDeniedException("not your document");
    }
    return ResponseEntity.ok(doc);
}
