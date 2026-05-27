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
public class SubCA extends CA{

    static SubCA getInstance(String role, Properties get, String property, RootCA root) {
        int days = getInt(get.getProperty("default_days", ""+10*365));
        return getInstance(role, get, property, root,days);      
    }
    
    static SubCA getInstance(String role, Properties get, String property, RootCA root, int days) {
        days = getInt(get.getProperty("default_days", ""+days));
        SubCA ca = new SubCA(root,days);
              ca.prop=get;
              ca.validate_config(role, get, property);
        return ca;      
    }
    
    public SubCA(RootCA root, int days) {
        this(days);
        this.rootCA=root;
    }
    public SubCA(RootCA root) {
        this();
        this.rootCA=root;
    }
    public SubCA(int days) {
        super(days);
        this.master=false;
    }
    public SubCA() {
        this(10);
    }
}
