package com.detzerg.firmaelectronica;

import com.detzerg.firmaelectronica.XAdESBESSignature;
import java.io.File;

public class Main {
    public static void main(String[] args) {
        String fileOutput = "";
        String xmlPath = "";
        String p12FilePath = "";
        String p12Password = "";

        if (args.length < 3) {
            System.out.println("Error=Especifique <XMLFilePath> <P12FilePath> <PWP12> <?OutPutXML>");
            return;
        }

        xmlPath = args[0];
        p12FilePath = args[1];
        p12Password = args[2];

        if (args.length == 4) {
            fileOutput = args[3];
        }

        File xml = new File(xmlPath);
        File p12File = new File(p12FilePath);

        if (!xml.exists()) {
            System.out.println("Error=XML file not found in this path");
            System.out.println("\tNot found in: "+xml.getAbsolutePath());
            return;
        }

        if (!p12File.exists()) {
            System.out.println("Error=P12 file not found in this path");
            System.out.println("\tNot found .P12 in: " + p12File.getAbsolutePath());
            return;
        } 

        signFile(xml, p12FilePath, p12Password, fileOutput);
    }

    public static void signFile(File xml, String p12File, String p12Password, String output) {
        try {
            XAdESBESSignature xadesBesFirma = 
                new XAdESBESSignature(); 

            String outputPath = ""; //path de salida del archivo firmado

            if (output.equals("")) {
                // Si el path esta vacio se exporta en la carpeta del archivo de entrada
                outputPath = xml.getAbsolutePath()
                                .replace(xml.getName(), "")+"/signed";
            } else {
                outputPath = output;
            }

            // Si la carpteta de salida no existe, la crea
            File outputPathFolder = new File(outputPath);
            if (!outputPathFolder.exists()) {
                outputPathFolder.mkdir();
            }
            // procesa el firmado
            xadesBesFirma.firmar(xml.getAbsolutePath(), xml.getName(), outputPath, p12File, p12Password);
        } catch (Exception e) {
            System.out.println("Error=Unknow error, verify your XML File, P12 File and Password");
            return;
        }
    }
}
