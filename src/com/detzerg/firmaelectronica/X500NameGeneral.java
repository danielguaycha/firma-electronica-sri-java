package com.detzerg.firmaelectronica;

import java.util.StringTokenizer;

public class X500NameGeneral {

    private String CN = null;
    private String OU = null;
    private String O = null;
    private String L = null;
    private String ST = null;
    private String C = null;

    public X500NameGeneral(String name) {
        StringTokenizer st = new StringTokenizer(name, ",");

        while (st.hasMoreTokens()) {
            String token = st.nextToken().trim();
            int idx = token.indexOf("=");
            if (idx >= 0) {
                String label = token.substring(0, idx);
                String value = token.substring(idx + 1);

                if ("CN".equals(label)) {
                    this.CN = value;
                    continue;
                }
                if ("OU".equals(label)) {
                    this.OU = value;
                    continue;
                }
                if ("O".equals(label)) {
                    this.O = value;
                    continue;
                }
                if ("C".equals(label)) {
                    this.C = value;
                    continue;
                }
                if ("L".equals(label)) {
                    this.L = value;
                    continue;
                }
                if ("ST".equals(label)) {
                    this.ST = value;
                }
            }
        }
    }

    public String getC() {
        return this.C;
    }

    public String getCN() {
        return this.CN;
    }

    public String getL() {
        return this.L;
    }

    public String getO() {
        return this.O;
    }

    public String getOU() {
        return this.OU;
    }

    public String getST() {
        return this.ST;
    }
}
