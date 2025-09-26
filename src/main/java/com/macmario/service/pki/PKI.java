/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */

package com.macmario.service.pki;

import com.macmario.io.file.ReadFile;
import com.macmario.io.thread.RunnableT;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Properties;

/**
 *
 * @author MNO
 */
public class PKI extends PKIVersion {
    
    private CA ca = new CA(365);

    public static void main(String[] args) throws Exception{
        
        if ( args.length >0 ) {
            PKI pki = new PKI();
            for (int i=0; i<args.length; i++ ) {
               if ( args[i].equals("-d") ) { pki.debug++; }
               else if ( args[i].equals("-conf")   ) { pki.config=args[++i]; }
               else if ( args[i].equals("-run")    ) { pki.run=true; }
               else if ( args[i].equals("-sign")   ) { pki.sign=true; }
               else if ( args[i].equals("-create") ) { pki.create=true; }
               else if ( args[i].equals("-csr")    ) { 
                   KeyPair pair = pki.ca.generateKeyPair();
                   String dn = args[++i];
                   String email = null;
                   String dns = null;
                   String file="request"+pki.getRandomNumber();
                   for (int j=i; i<args.length; j++, i++ ) {
                       if ( args[j].equals("-file")      ) { i++; file=args[++j]; }
                       else if ( args[j].equals("-email")
                              || args[j].equals("-mail") ) { i++; email=args[++j]; }
                       else if ( args[j].equals("-dns")  ) { i++;   dns=args[++j]; }
                   }
                   System.out.println("INFO: like to create certifcate request");
                   System.out.println("\t\tfile: \t\t"+file);
                   System.out.println("\t\taltDNSName:\t"+dns);
                   System.out.println("\t\taltRFC822:\t"+email);
                   if ( pki.ca.storeCSR(pki.ca.generateCSR(pair, dn, email, dns),file) ) {
                        System.out.println("INFO: certifcate request created");
                        System.out.println("\t\tCertificate Request:\t"+file);
                        System.out.println("\t\tPublic  Key:\t\t"+file+".key.pub");
                        System.out.println("\t\tPrivate Key:\t\t"+file+".key.priv");
                        pki.ca.storePublicKey(pair.getPublic(), file+".key.pub");
                        pki.ca.storePrivateKey(pair.getPrivate(), file+".key.priv");
                   }
                   System.out.println("done");
                   System.exit(0); 
               }
            }
            if ( pki.run || pki.sign || pki.create ) {
                 pki.evaluate();
            } else {
                 usage();
            }
        } else {
            usage();
        }    
    }
    
    private void evaluate(){
        if ( isNotNullOrEmpty(config) ) {
            ReadFile rf = new ReadFile(config);
            HashMap<String, Properties> ma = rf.getConfigParts();
            Properties p = ma.get("global");
            
            for ( String role: p.getProperty("role", "root").split(",")) {
                if ( role.contains("sub")) {
                    Properties p1=((ma.get( role )==null)?ma.get("config"):ma.get( role ));
                    SubCA ca = SubCA.getInstance(role, 
                                                 ma.get( p1.getProperty("default_ca") ), 
                                                 p.getProperty("dir", System.getProperty("user.dir")),
                                                 this.rootCA
                    );
                    this.subCAs.add(ca);
                } 
                else if ( role.contains("master") || role.contains("root") ){
                   Properties p1=((ma.get( role )==null)?ma.get("config"):ma.get( role ));
                   this.rootCA = RootCA.getInstance(role, 
                                                    ma.get( p1.getProperty("default_ca") ), 
                                                    p.getProperty("dir", System.getProperty("user.dir"))
                   );
                }
                
            }        
               
            if ( this.rootCA == null ) { System.out.println("INFO: missing rootCA - run in Sub-Mode only"); }
            
            if ( run  ) { runPKI(false);  } else {
                if ( sign ) {                     
                    runPKI(true);                    
                }
            }
        } else {
            System.out.println("ERROR: missing config");
            usage();
        }
    }
    
    
    private void runPKI(boolean b){
        PKIThread pkt = new PKIThread(this);
                  pkt.start();
                  if ( b ) {
                      pkt.setClosedAfterRun();
                  } 
                  pkt.wait4Closed();
                   
    }
    
    
    private static void usage() {
        System.out.println(" usage()  ");
        System.out.println(getInfo()+"\n\nOptions:\n"
                +"\t-conf <config-file>\t:\tprovide pki information\n"
                +"\t-sign \t\t\t:\tsign open certificate request - single step\n"
                +"\t-run \t\t\t:\tsign on demond for open/new certificate request (loop until break)\n"
                +"\n\n\t-csr <dn> [-email <email>] [-dns <dns entry>] <file>\n"
                +"\n\t\t\t\tcreate certificate request and store csr/public & private key"
        );
        
                
        System.exit(-1);
    }
    
    private String config="";
    private boolean    run=false;
    private boolean   sign=false;
    private boolean create=false;
    
    private RootCA           rootCA=null;
    private ArrayList<SubCA> subCAs=new ArrayList<>();

    
    
    private class PKIThread extends RunnableT {

        private final PKI pki;
        private boolean couldClose=false;

        PKIThread(PKI pki){
            this.pki=pki;
        }
        
        @Override
        public void run() {
            setRunning();
            while( ! isClosed() ) {
                try {
                    pki.rootCA.checkSigning(); 
                    for(SubCA ca: pki.subCAs ) {
                        ca.checkSigning();
                    }
                    if ( this.couldClose ) { setClosed(); }
                    if ( ! isClosed()    ) { sleep(3000); }
                }catch(Exception e){
                    setClosed();
                }
            }
            
        }
        
        void setClosedAfterRun() { this.couldClose=true; }
        void wait4Closed(){
            while( ! isClosed() ) {  sleep(300); }
        }
    }
}
