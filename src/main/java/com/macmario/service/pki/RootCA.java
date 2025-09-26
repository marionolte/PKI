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
public class RootCA extends CA{

    static RootCA getInstance(String role, Properties get, String property) {
        RootCA ca = new RootCA();
               ca.prop=get;
               ca.validate_config(role, get, property);
        return ca; 
    }
    
    public RootCA() {
        super(32);
        this.master=true;
    }
}
