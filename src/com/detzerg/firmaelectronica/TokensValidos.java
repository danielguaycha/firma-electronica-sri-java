package com.detzerg.firmaelectronica;

public enum TokensValidos {
    ANF1("ANF - Certificado Exportado"),
    ANF_TOKEN("ANF - Plug & Sign"),
    BCE_IKEY2032("BCE - iKey2032"),
    BCE_ALADDIN("BCE - Aladdin eToken Pro"),
    SD_EPASS3000("SD - ePass3003 auto"),
    SD_BIOPASS("SD - BioPass3000"),
    KEY4_CONSEJO_JUDICATURA("KEY4 - Consejo Judicatura");

    String id;

    TokensValidos(String modelo) {
        this.id = modelo;
    }

    public String getId() {
        return this.id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String toString() {
        return getId();
    }

    public static TokensValidos obtenerToken(String modelo) {
        for (TokensValidos tokenValido : values()) {

            if (tokenValido.name().equals(modelo)) {
                return tokenValido;
            }
        }
        return null;
    }
}
