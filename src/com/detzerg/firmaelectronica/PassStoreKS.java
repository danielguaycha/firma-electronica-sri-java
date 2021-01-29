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
package com.detzerg.firmaelectronica;

import es.mityc.javasign.pkstore.IPassStoreKS;
import java.security.cert.X509Certificate;


public class PassStoreKS implements IPassStoreKS {

    /**
     * Contraseña de acceso al almacén.
     */
    private transient String password;

    /**
     * <p>
     * Crea una instancia con la contraseña que se utilizará con el almacén
     * relacionado.</p>
     *
     * @param pass Contraseña del almacén
     */
    public PassStoreKS(final String pass) {
        this.password = new String(pass);
    }

    /**
     * <p>
     * Devuelve la contraseña configurada para este almacén.</p>
     *
     * @param certificate No se utiliza
     * @param alias no se utiliza
     * @return contraseña configurada para este almacén
     * @see
     * es.mityc.javasign.pkstore.IPassStoreKS#getPassword(java.security.cert.X509Certificate,
     * java.lang.String)
     */
    public char[] getPassword(final X509Certificate certificate, final String alias) {
        return password.toCharArray();
    }

}
