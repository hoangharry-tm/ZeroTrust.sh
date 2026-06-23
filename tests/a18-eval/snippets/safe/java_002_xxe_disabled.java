import javax.xml.parsers.*;
public Document parseXML(InputStream input) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setXIncludeAware(false);
    DocumentBuilder builder = factory.newDocumentBuilder();
    return builder.parse(input);
}
