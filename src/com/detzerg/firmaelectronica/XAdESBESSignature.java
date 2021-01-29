package com.detzerg.firmaelectronica;

/*
 * Copyright (C) 2014 
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


import org.w3c.dom.Document;
import es.mityc.firmaJava.libreria.xades.DataToSign;
import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.javasign.EnumFormatoFirma;
import es.mityc.javasign.xml.refs.InternObjectToSign;
import es.mityc.javasign.xml.refs.ObjectToSign;

public class XAdESBESSignature extends GenericXMLSignature {

    /**
     * <p>
     * Recurso a firmar
     * </p>
     */
    private String RESOURCE_TO_SIGN;

    /**
     * <p>
     * Fichero donde se desea guardar la firma
     * </p>
     */
    private String SIGN_FILE_NAME;

    public  void setRESOURCE_TO_SIGN(String RESOURCE_TO_SIGN) {
        RESOURCE_TO_SIGN = RESOURCE_TO_SIGN;
    }

    public  void setSIGN_FILE_NAME(String SIGN_FILE_NAME) {
        SIGN_FILE_NAME = SIGN_FILE_NAME;
    }

    /**
     * <p>
     * Firma el archivo XML
     * </p>
     *
     * @param urlArchivo
     * @param nombreArchivo
     * @param urlOutArchivo
     * @return 
     */
    public boolean firmar(String urlArchivo,String nombreArchivo,String urlOutArchivo,String PKCS12_RESOURCE,String PKCS12_PASSWORD) {
        XAdESBESSignature signature = new XAdESBESSignature();
        signature.RESOURCE_TO_SIGN=urlArchivo;
        signature.SIGN_FILE_NAME=nombreArchivo;
        
        signature.setOUTPUT_DIRECTORY(urlOutArchivo);
        signature.PKCS12_RESOURCE=PKCS12_RESOURCE;
        signature.PKCS12_PASSWORD=PKCS12_PASSWORD;
        return signature.execute();
        
    }

    public XAdESBESSignature() {
    }

    @Override
    protected DataToSign createDataToSign() {
        DataToSign dataToSign = new DataToSign();
        dataToSign.setXadesFormat(EnumFormatoFirma.XAdES_BES);
        dataToSign.setEsquema(XAdESSchemas.XAdES_132);
        dataToSign.setXMLEncoding("UTF-8");
        // Se añade un rol de firma
       // dataToSign.addClaimedRol(new SimpleClaimedRole("Rol de firma"));                
        dataToSign.setEnveloped(true);
        dataToSign.addObject(new ObjectToSign(new InternObjectToSign("comprobante"), "contenido comprobante", null, "text/xml", null));
        dataToSign.setParentSignNode("comprobante");
        Document docToSign = getDocument(RESOURCE_TO_SIGN);
        dataToSign.setDocument(docToSign);
        return dataToSign;
    }

    @Override
    protected String getSignatureFileName() {
        return SIGN_FILE_NAME;
    }
}
