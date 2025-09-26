/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.macmario.service.pki;

import java.util.Random;

/**
 *
 * @author MNO
 */
public class PKIVersion extends com.macmario.general.Version{
    static private final String progVersion="0.1";
    static private final String progName="PKI";
    private Random rand =  new Random();
    
    public int getRandomNumber() { return rand.nextInt(9999); }   
     
    static String getProductVersion(){ return progVersion; }
    static String getProduct(){ return progName; }
    
    
    public static String getInfo(){ 
        String[] sp = jarfile.split("/");
        return mhservice.replaceAll("OC.jar", sp[sp.length-1])+" - "+getProduct()+" "+getProductVersion()+" - "+getProductAuthor();
    }
}
