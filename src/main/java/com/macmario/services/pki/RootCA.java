/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.macmario.services.pki;

import java.util.Properties;

/**
 *
 * @author SuMario
 */
public class RootCA extends CA{

    static RootCA getInstance(String role, Properties get, String property) {
        int days = getInt(get.getProperty("default_days", ""+30*365));
        return getInstance(role, get, property,days); 
    }
    static RootCA getInstance(String role, Properties get, String property,int days) {
        RootCA ca = new RootCA(days);
               ca.prop=get;
               ca.validate_config(role, get, property);
        return ca; 
    }
    
    public RootCA(int days){
        super(days);
        this.master=true;
    }
    public RootCA() {
        this(32);
    }
}
