package com.hqb.commonlib.xml;

import static org.junit.Assert.*;

import java.io.IOException;



import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.xml.sax.SAXException;

public class GenericXmlSchemaValidatorTest {

	private static final String TEST_EMPLOYEE_XML = "xml/validator/test-employee.xml";

	private static final String TEST_EMPLOYEE_SCHEMA_XSD = "xml/validator/test-employee.xsd";

	private XmlSchemaValidator validator;
	
	@Rule
	public ExpectedException exception = ExpectedException.none();
	
	@Before
	public void setup(){
		validator = new GenericXmlSchemaValidator();
	}
	
	@Test
	public void givenSourceXmlToNullShouldThrowNullPointerException() throws SAXException {
		String sourceXml = null;
		
		exception.expect(NullPointerException.class);
		validator.valid(sourceXml, TEST_EMPLOYEE_SCHEMA_XSD);
	}
	
	@Test
	public void givenSchemaFileToNullShouldThrowNullPointerException() throws SAXException {
		String sourceXml = TEST_EMPLOYEE_XML;
		String schemaFile = null;
		exception.expect(NullPointerException.class);
		validator.valid(sourceXml, schemaFile);
	}
	
	@Test
	public void givenBothFileShouldValidAndReturnTrue() throws SAXException{
		String sourceXml = TEST_EMPLOYEE_XML;
		String schemaFile = TEST_EMPLOYEE_SCHEMA_XSD;
		
		Assert.assertTrue(validator.valid(sourceXml, schemaFile));
		
	}

}
