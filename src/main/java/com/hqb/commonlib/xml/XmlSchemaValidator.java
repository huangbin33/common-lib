package com.hqb.commonlib.xml;

import java.io.File;

import org.xml.sax.SAXException;

public interface XmlSchemaValidator {
	boolean valid(String sourceXml, String schemaFile) throws SAXException;

	boolean valid(File sourceXml, File schemaFile) throws SAXException;
}