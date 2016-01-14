package com.hqb.commonlib.xml;

import java.io.File;
import java.io.IOException;
import java.net.URL;

import javax.xml.XMLConstants;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import org.xml.sax.SAXException;

public class GenericXmlSchemaValidator implements XmlSchemaValidator {

	@Override
	public boolean valid(String sourceXml, String schemaFile) throws SAXException {
		URL xmlUrl = Thread.currentThread().getContextClassLoader().getResource(sourceXml);
		File xmlFile = new File(xmlUrl.getPath());
		
		URL schemaUrl = Thread.currentThread().getContextClassLoader().getResource(schemaFile);
		File xsdFile = new File(schemaUrl.getPath());
		return valid(xmlFile, xsdFile);
	}

	@Override
	public boolean valid(File sourceXml, File schemaFile) throws SAXException {
		SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
		Schema schema = factory.newSchema(schemaFile);
		Validator validator = schema.newValidator();
		try {
			validator.validate(new StreamSource(sourceXml));
		} catch (IOException e) {
			return false;
		}
		return true;
	}

}
