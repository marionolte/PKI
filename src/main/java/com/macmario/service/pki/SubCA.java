/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.macmario.service.pki;

import java.util.Properties;

/**
 *
 * @author SuMario
 */
public class SubCA extends CA{

    static SubCA getInstance(String role, Properties get, String property, RootCA root) {
        SubCA ca = new SubCA(root);
              ca.prop=get;
              ca.validate_config(role, get, property);
        return ca;      
    }
    
    public SubCA(RootCA root) {
        this();
        this.rootCA=root;
    }
    public SubCA() {
        super(10);
        this.master=false;
    }
}
