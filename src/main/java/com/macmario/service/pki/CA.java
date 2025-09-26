package com.macmario.service.pki;

import com.macmario.io.file.ReadDir;
import com.macmario.io.file.ReadFile;
import com.macmario.io.file.WriteFile;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import org.bouncycastle.asn1.ASN1Encodable;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemReader;


/**
 *
 * @author SuMario
 */
class CA extends PKIVersion{

    RootCA rootCA = null;
    boolean master=false;
    
    int days;
    int kLength;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private X509Certificate cert;
            Properties prop;
    private ReadDir BASEDIR;
    
    
    CA(int days) { this(days,4096); }
    CA(int days,int len) {
        this.days=days;
        this.kLength=len;
        
        Security.addProvider(new BouncyCastleProvider());
    }
    
    public KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
            keyGen.initialize((kLength>=4096)?kLength:4096);
            return keyGen.generateKeyPair();
        }catch(NoSuchAlgorithmException| NoSuchProviderException io){
            log(1, "ERROR: generating KeyPair - "+io.getMessage());
        }   
        return null;
    }
    
    public X509Certificate generateSelfSignedCert(KeyPair pair, String dn) {
        try {
            X500Name issuer = new X500Name(dn);
            BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
            Date notBefore = new Date();
            Date notAfter  = new Date( (System.currentTimeMillis()+(days*24*60*60*1000L)-1000) );

            X509v3CertificateBuilder cB = new JcaX509v3CertificateBuilder(
                    issuer, serial, notBefore,notAfter, issuer,pair.getPublic()
            );

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate());

            return new JcaX509CertificateConverter().setProvider("BC").getCertificate(cB.build(signer));
        } catch(OperatorCreationException| NullPointerException| CertificateException io){
           log(1, "ERROR: could not generate root certificate for "+dn+" - "+io.getMessage()); 
        }
        return null;
    }
    
    public X509Certificate generateSignedCert(PKCS10CertificationRequest csr,PublicKey pubKey, PrivateKey privCAKey, X509Certificate caCert, String dn, int maxDays) {
      try {  
        X500Name issuer  = new X500Name(caCert.getSubjectX500Principal().getName());
        X500Name subject = new X500Name(dn);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();
        Date notAfter  = new Date( (System.currentTimeMillis()+(maxDays*24*60*60*1000L)-1000) );
        
        X509v3CertificateBuilder cB = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore,notAfter, subject, pubKey
        );
        readCSRAltNames(csr,cB);
        addExtensions(cB);
        
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(privCAKey);
        
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(cB.build(signer));
        
      }catch(OperatorCreationException| CertificateException io){
          log(1, "ERROR: could not generate certificate for "+dn+" - "+io.getMessage());
      }  
      return null;
    }
    
    private void addExtensions(X509v3CertificateBuilder cB){
        String url = prop.getProperty("crlUrl");
        if ( isNotNullOrEmpty(url) ) {
            DistributionPointName dpName = new DistributionPointName (
                    new GeneralNames( new GeneralName(GeneralName.uniformResourceIdentifier,url))
            );
            DistributionPoint dPoint = new DistributionPoint(dpName, null, null);
            CRLDistPoint crlPoint = new CRLDistPoint(new DistributionPoint[]{ dPoint });
          try{  
            cB.addExtension(Extension.cRLDistributionPoints, false, crlPoint);
          } catch(CertIOException|NullPointerException io){
            log(1,"could not add crl extension - "+io.getMessage());
          }   
        }
        
        url = prop.getProperty("ocspUrl");
        if ( isNotNullOrEmpty(url) ) {
            AccessDescription ocspAccess = new AccessDescription(
                    AccessDescription.id_ad_ocsp,
                    new GeneralName( GeneralName.uniformResourceIdentifier,url)
            );
            
            AuthorityInformationAccess aia = new AuthorityInformationAccess(ocspAccess);
            
            try{  
              cB.addExtension(Extension.authorityInfoAccess, false, aia);
            } catch(CertIOException|NullPointerException io){
              log(1,"could not add crl extension - "+io.getMessage());
            }  
        }
    }
    
    private void readCSRAltNames(PKCS10CertificationRequest csr, X509v3CertificateBuilder cB){
        GeneralNames san = null;
        
        for(Attribute attr : csr.getAttributes() ) {
            if ( attr.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
                ASN1Encodable[] values = attr.getAttributeValues();
                if ( values != null && values.length>0 ){
                    Extensions ext = Extensions.getInstance(values[0]);
                    Extension sExt = ext.getExtension(Extension.subjectAlternativeName);
                    if ( sExt != null ) {
                        san =GeneralNames.getInstance(sExt.getParsedValue());
                    }
                }
            }
        }        
        try {
         if ( san != null)
            cB.addExtension(Extension.subjectAlternativeName, false, san);
        } catch(CertIOException|NullPointerException io){
            log(1,"could not add subaltnames extension - "+io.getMessage());
        } 
    }
    
    public PKCS10CertificationRequest generateCSR(KeyPair pair,String dn, String email, String dns){
        PKCS10CertificationRequest csr = null;
        try {
            X500Name subject=new X500Name(dn);
            
            GeneralNames san=null;
            if ( isNotNullOrEmpty(email) || isNotNullOrEmpty(dns)){
                if (isNotNullOrEmpty(email) && isNotNullOrEmpty(dns)){
                    san = new GeneralNames( new GeneralName[]{
                            new GeneralName(GeneralName.rfc822Name, email),
                            new GeneralName(GeneralName.dNSName, dns)
                    });
                }
                else if ( isNotNullOrEmpty(email) ) {
                    san = new GeneralNames( new GeneralName[]{
                            new GeneralName(GeneralName.rfc822Name, email)  
                    });
                }
                else if ( isNotNullOrEmpty(dns) ) {
                    san = new GeneralNames( new GeneralName[]{
                            new GeneralName(GeneralName.dNSName, dns)
                    });
                }
            }
        
            PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(subject, pair.getPublic());
            if ( san != null ) {
                ExtensionsGenerator extGen = new ExtensionsGenerator();                
                extGen.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, false,san);
                csrBuilder.addAttribute(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
            }
                    
           ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate());
           csr= csrBuilder.build(signer);
        } catch(java.io.IOException|OperatorCreationException|NullPointerException io){
             log(1, "ERROR: could not generate csr for "+dn+" - "+io.getMessage());
        }   
                    
        return csr;
    }
    
    public boolean storeCSR(PKCS10CertificationRequest csr, String filename){
        if ( csr == null ) {
            System.out.println("ERROR: certificate request is null - do not store in "+filename);
            return false;
        }
        try{
            JcaPEMWriter write = new JcaPEMWriter(new FileWriter(filename));
                         write.writeObject(csr);
                         write.flush();
                         write.close();
        }catch(IOException| NullPointerException io){
           log(1,"ERROR: could not store public key to file "+filename+" - "+io.getMessage()); 
           return false;
        }
        return true;
    }
    
    public PKCS10CertificationRequest loadCSR(String filename){
        PKCS10CertificationRequest csr=null;
        try{
            PemReader pRead = new PemReader(new FileReader(filename));
                      csr = new PKCS10CertificationRequest(pRead.readPemObject().getContent());   
        }catch(IOException| NullPointerException io){
           log(1,"ERROR: could not store public key to file "+filename+" - "+io.getMessage()); 
        }
        return csr;
    }
    
    public boolean validCSR(String filename) throws IOException  {
        return validCSR( this.loadCSR(filename) );
    }    
    public boolean validCSR(PKCS10CertificationRequest csr) {    
        boolean isValid =false;
        if ( isNotNullOrEmpty(csr)){
            JcaPKCS10CertificationRequest jcaR = new JcaPKCS10CertificationRequest(csr);
            String subject = jcaR.getSubject().toString();
            try {
                isValid = jcaR.isSignatureValid(
                        new JcaContentVerifierProviderBuilder().setProvider("BC").build(jcaR.getPublicKey())
                );
                
                if ( isValid ) {
                    isValid = isMinKeyLength((RSAPublicKey)jcaR.getPublicKey());
                }  
                if ( isValid ) {
                    isValid = this.isCSRSignatureAlgorithmValid(csr, prop.getProperty("defsult_md", "sha256"));
                } 
                if ( isValid ) {
                    String[] sp = subject.split(",");
                    for(String s:sp) {
                        if ( s.toLowerCase().startsWith("cn=") ) {
                            String d=prop.getProperty("domain").toLowerCase();
                            s=s.substring("cn*".length()).replaceAll(" ", "");
                            if ( ! s.endsWith("@"+d) && ! s.endsWith("."+d) ) {
                                System.out.println("ERROR: csr request - "+subject+" - cn does not match as part of domain "+d);
                                isValid=false; 
                            }
                        }
                    }
                    boolean uR=isUserRequest(jcaR.getSubject());
                    if( isValid && uR) {
                        String email = getUserEmail(csr);
                        if ( email != null ) {
                            String d=prop.getProperty("domain"); 
                            if ( d!=null &&! email.toLowerCase().endsWith("@"+d.toLowerCase())) { 
                                System.out.println("ERROR: csr request - "+subject+" - user does not match as part of domain "+d);
                                isValid=false; 
                            }
                        }
                    } 
                    if ( isValid && !uR) {
                        String[] dns = getDNSEntries(csr);
                        String d=prop.getProperty("domain"); 
                        if ( isNotNullOrEmpty(dns) && d != null ) {
                            d=d.toLowerCase();
                            for(String ho:dns){
                                if (! ho.toLowerCase().endsWith("."+d) ) { 
                                    System.out.println("ERROR: csr request - "+subject+" - host does not match as part of domain "+d);
                                    isValid=false; 
                                }
                            }
                        }
                    }
                }
            } catch(InvalidKeyException| NoSuchAlgorithmException| PKCSException| OperatorCreationException io) {
                log(1,"ERROR: csr validation failed with Exception - "+io.getMessage());
                isValid=false;
            }    
        }
        
        return isValid;
    }
    
    public boolean isUserRequest(X500Name name){
        return name.toString().contains("emailAddress=");
    }
    
    public String getUserEmail(PKCS10CertificationRequest csr){
        try {
            ASN1Set extensions = csr.getAttributes()[0].getAttrValues();
            for( int i=0; i<extensions.size(); i++){
                ASN1Encodable ext = extensions.getObjectAt(i);
                if ( ext instanceof GeneralNames ){
                    for ( GeneralName name : ((GeneralNames)ext).getNames() ){
                        if ( name.getTagNo() == GeneralName.rfc822Name ) { return name.getName().toString(); }
                    }
                }
            }
        } catch( ArrayIndexOutOfBoundsException io ) {
            log(1," no attributes in certificate request - email check");
        }    
        return "";
    }
    
    public String[] getDNSEntries(PKCS10CertificationRequest csr){       
        ArrayList<String> ar = new ArrayList<>();
        try {
         ASN1Set extensions = csr.getAttributes()[0].getAttrValues();
         for( int i=0; i<extensions.size(); i++){
            ASN1Encodable ext = extensions.getObjectAt(i);
            if ( ext instanceof GeneralNames ){
                for ( GeneralName name : ((GeneralNames)ext).getNames() ){
                    if ( name.getTagNo() == GeneralName.dNSName ) { ar.add( name.getName().toString()); }
                }
            }
         }     
        } catch( ArrayIndexOutOfBoundsException io ) {
            log(1," no attributes in certificate request - dns check");
        }         
        return getStringArray(ar);
    }
    
    public boolean isMinKeyLength(RSAPublicKey key) {
        int len = key.getModulus().bitLength();        
        log(1,"compare key length greater 4096 :"+( (len >=4096)?"Yes":"No" )+":");
        return ( len >=4096 );
    }
    
    public boolean isCSRSignatureAlgorithmValid(PKCS10CertificationRequest csr, String sig){
        
        String sigID=csr.getSignatureAlgorithm().getAlgorithm().getId();
        log(1,"compare sigID:"+sigID+":  with requested :"+sig+":");
        if ( sig.toLowerCase().contains("sha") && sigID.equals("1.2.840.113549.1.1.11") ) {return true;}        
        return false;
    }
    
    HashMap<String, String> certmap=new HashMap<>();
    private boolean certmapLoaded=false;
    private long certNextID=1L;
    void storeCRTIntStore(X509Certificate crt){
        if ( isNullOrEmpty(crt) ) {
            log(1,"storeCRTIntStore() - ERROR: no certificate - skip db update "); 
            return;
        }
        String db     = prop.getProperty("database"    , this.BASEDIR.getAbsolutePath()+_FS+"certindex.txt");
        loadCertMap(db);
        String newDir = prop.getProperty("new_cert_dir", this.BASEDIR.getAbsolutePath()+_FS+"certs");
        log(1,"storeCRTIntStore() - DB:"+db);
        log(1,"storeCRTIntStore() - CERTSDIR:"+newDir);
        String name=crt.getSubjectX500Principal().getName();
        long id = getCertDBid(name);
        log(1,"like to store certificate from:"+name+":  with id:"+id+":");
        addCertToStore(id,name,crt,db,newDir);
        if ( id == certNextID ) { certNextID++; }
        
    }
    
    private long getCertDBid(String name){
        if ( isNotNullOrEmpty(certmap)) {
            log(1,"like to find certificate :"+name+":  in store:");
            for(Map.Entry<String,String> entry : certmap.entrySet() ){
                if ( entry.getValue().equals(name) ) { return getLong(entry.getKey()); }
            }
        }    
        return certNextID;
    }
    
    private void addCertToStore(long id, String name, X509Certificate crt, String db, String certDir) {
        this.storeCert(crt, certDir+_FS+id);
        WriteFile wf=new WriteFile(db);
                  wf.append(""+id+":"+name+"\n");
    }
    
    private void loadCertMap(String db){
        if ( ! certmapLoaded ) {
            String last="1";
            ReadFile rf = new ReadFile(db);
            if ( rf.isReadableFile() ) {
            
                for(String s: rf.readOut().toString().split("\n")){
                    s=s.trim();
                    String[] sp=s.split(":");
                    String k=sp[0]; 
                    certmap.put(k, s.substring(k.length()+1));
                    last=k;
                }
            } else {
                rf.create(true);
            }
            certNextID=getLong(last)+1;
            certmapLoaded=true;
        }        
    }
    
    public X509Certificate signCSR(String filename){  return signCSR(loadCSR(filename) ); }
    public X509Certificate signCSR(PKCS10CertificationRequest csr){  
        X509Certificate crt=null;
        try {
          if ( csr != null ) {
            if ( validCSR(csr) ) {
                JcaPKCS10CertificationRequest jca = new JcaPKCS10CertificationRequest(csr);
                log(1,"signCSR() csr subject->"+jca.getSubject().toString());
                crt = this.generateSignedCert(
                            csr,
                            jca.getPublicKey(), 
                            privateKey, 
                            this.cert, 
                            jca.getSubject().toString(), 
                            getInt(prop.getProperty("default_days", "365")) 
                    );
                log(1,"signCSR() certificate created ->"+( (crt!=null)?"Yes":"No"));
                storeCRTIntStore(crt);
                log(1,"signCSR() certificate stored");
            }    
          } else {
              log(1,"ERROR: could not generate certificate - csr is NULL");
          }
        } catch(InvalidKeyException|NoSuchAlgorithmException|NullPointerException io){
            log(1,"ERROR: could not generate certificate - "+io.getMessage());
        }  
        return crt; 
    }
    
    public String getBase64(byte[] b) {
        String s = Base64.getEncoder().encodeToString(b);
        StringBuilder sw = new StringBuilder();
        for ( int i=0; i<s.length(); i++ ){
            if ( i % 64 == 0) { sw.append("\n"); }
            sw.append(s.charAt(i));
        }
        return sw.toString();
    }
    
    public byte[] getUnBase64(String b) {
        return Base64.getDecoder().decode(b);
    }
    
    public void storeCert(X509Certificate cert, String filename) {
       try { 
        try(FileOutputStream fos = new FileOutputStream(filename)){
            fos.write(getPEMFormat(cert.getEncoded(),"cert").getBytes());
        }
       }catch(IOException| NullPointerException|CertificateEncodingException io ){
           log(1,"ERROR: could not store certificate to file "+filename+" - "+io.getMessage()); 
       } 
    }
    public void storePrivateKey(PrivateKey key, String filename) {
        try{
            FileOutputStream fos = new FileOutputStream(filename);
            fos.write(getPEMFormat(key.getEncoded(),"priv").getBytes());
        }catch(IOException| NullPointerException io){
           log(1,"ERROR: could not store private key to file "+filename+" - "+io.getMessage()); 
        }
    }
    public void storePublicKey(PublicKey key, String filename)  {
        try{
            FileOutputStream fos = new FileOutputStream(filename);
            fos.write(getPEMFormat(key.getEncoded(),"pub").getBytes());
        }catch(IOException| NullPointerException io){
           log(1,"ERROR: could not store public key to file "+filename+" - "+io.getMessage()); 
        }
    }
    
    private String getPEMFormat(byte[] b, String typ) {
        StringBuilder sw = new StringBuilder();
        switch(typ) {
            case "cert":  { sw.append("-----BEGIN CERTIFICATE-----"); break;}
            case "pub":   { sw.append("-----BEGIN PUBLIC KEY-----"); break;}
            case "priv":  { sw.append("-----BEGIN PRIVATE KEY-----"); break;}
            case "csr":   { sw.append("-----BEGIN CERTIFICATE REQUEST-----"); break;}
            default:{break;} 
        }
        sw.append( getBase64(b) );
        switch(typ) {
            case "cert":  { sw.append("\n-----END CERTIFICATE-----\n"); break;}
            case "pub":   { sw.append("\n-----END PUBLIC KEY-----\n"); break;}
            case "priv":  { sw.append("\n-----END PRIVATE KEY-----\n"); break;}
            case "csr":   { sw.append("\n-----END CERTIFICATE REQUEST-----\n"); break;}
            default:{break;} 
        }        
        return sw.toString();
    }
    
    public PrivateKey loadPrivateKey(String filename){
        ReadFile rf = new ReadFile(filename);
        PrivateKey key=null;
        if ( rf.isReadableFile() ) {
          try{  
            StringBuilder sw = new StringBuilder();
            boolean start=false;
            for(String s: rf.readOut().toString().split("\n") ){
                s=s.trim();
                if ( start ){
                    if ( s.equals("-----END PRIVATE KEY-----") ) { start=false; }
                    else { sw.append(s); }
                } else {
                    if ( s.equals("-----BEGIN PRIVATE KEY-----") ) { start=true; }
                }
            }
            
            byte[] b = getUnBase64(sw.toString());
            PKCS8EncodedKeySpec keySpec= new PKCS8EncodedKeySpec(b);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            key= fact.generatePrivate(keySpec);
          
          }catch(InvalidKeySpecException|NoSuchAlgorithmException | NullPointerException io){
              log(1, "ERROR: could not load private key from "+filename+" - "+io.getMessage());
          }  
        }
        return key;
    }
    
    public PublicKey loadPublicKey(String filename){
        ReadFile rf = new ReadFile(filename);
        PublicKey key=null;
        if ( rf.isReadableFile() ) {
          try{  
            StringBuilder sw = new StringBuilder();
            boolean start=false;
            for(String s: rf.readOut().toString().split("\n") ){
                s=s.trim();
                if ( start ){
                    if ( s.equals("-----END PUBLIC KEY-----") ) { start=false; }
                    else { sw.append(s); }
                } else {
                    if ( s.equals("-----BEGIN PUBLIC KEY-----") ) { start=true; }
                }
            }
            
            byte[] b = getUnBase64(sw.toString());
            X509EncodedKeySpec keySpec= new X509EncodedKeySpec(b);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            key= fact.generatePublic(keySpec);
          
          }catch(InvalidKeySpecException|NoSuchAlgorithmException | NullPointerException io){
              log(1, "ERROR: could not load private key from "+filename+" - "+io.getMessage());
          }  
        }
        return key;
    }
    
    public X509Certificate loadCertificate(String filename){
        X509Certificate crt = null;
        try {
            FileInputStream fis = new FileInputStream(filename);
            CertificateFactory cF = CertificateFactory.getInstance("X.509");
            crt = (X509Certificate)cF.generateCertificate(fis);
        } catch(IOException|CertificateException|NullPointerException io ){
            log(1, "ERROR: could not load certificate from "+filename+" - "+io.getMessage());
        }
        return crt;
    }
    
    public String getDN() {
        StringBuilder ret=new StringBuilder();
            for ( String k : new String[]{"C","ST","L","O","OU","CN"} ){
                String v =prop.getProperty(k);
                if ( v != null ){
                    if ( ! ret.isEmpty() ) { ret.append(","); }
                    ret.append(k).append("=").append(v);
                }
            }
            log(1,"getDN() ->"+ret.toString()+"<-");
        return ret.toString();
    }
    
    public void validate_config(String role, Properties p, String path) {
        
        log(1,"role:"+role+": dir:"+path+"<-");
        log(1,"p->"+p);
        if ( isNotNullOrEmpty(p) ) {
            log(1,"path:"+path+"/"+role);
            ReadDir base = new ReadDir(path+"/"+role);
            if ( ! base.isDirectory() ) { 
                if ( base.mkdirs() ) {
                    log(1,"INFO: base directory "+base.getAbsolutePath()+" created");
                } else {
                    throw new PKIConfigException("ERROR: could not create base directory "+base.getAbsolutePath());
                }                 
            } else {
                log(1,"INFO: base directory "+base.getAbsolutePath()+" exist");
            }
            this.BASEDIR=base;
            for( String s : p.stringPropertyNames() ) {
                String v=stribeString(p.getProperty(s));                       
                if ( v.contains("$dir/") ) { v=v.replace("$dir/", path+"/"+role+"/"); }
                log(2,"CA Properties k:"+s+": =>"+p.getProperty(s)+"<= =>"+v+"<=");
                if ( ! p.getProperty(s).equals(v) ) { p.put(s, v); }
            }
            for ( String d : new String[]{ "req", "certs", "private","crl"} ) {
                 ReadDir mb = new ReadDir( base.getFile().getAbsolutePath()+"/"+d);
                 if ( ! mb.isDirectory() ) { mb.mkdirs(); }
            }
            ReadFile rf = new ReadFile(p.getProperty("private_key",base.getAbsolutePath()+"/private/cakey.pem"));
            if ( ! rf.isReadableFile() ) {
                KeyPair pair = generateKeyPair();
                if ( isNullOrEmpty(pair) ) {
                    throw new PKIConfigException("ERROR: could not generate BC KeyPair - NULL");
                }
                this.privateKey=pair.getPrivate();  storePrivateKey(this.privateKey, rf.getFile().getAbsolutePath());
                this.publicKey=pair.getPublic();    storePublicKey( this.publicKey,  rf.getFile().getAbsolutePath()+".pub");
                log(1, "is keypair generated ? "+((pair==null)?"No":"Yes"));
            } else {
                this.privateKey=loadPrivateKey(rf.getFile().getAbsolutePath());
                log(1, "is private key loaded ? "+((this.privateKey==null)?"No":"Yes"));
                this.publicKey =loadPublicKey(rf.getFile().getAbsolutePath()+".pub");
                log(1, "is public key loaded ? "+((this.publicKey==null)?"No":"Yes"));
            }
            
               rf = new ReadFile(p.getProperty("certificate",base.getAbsolutePath()+"/cacerts.pem"));
            if ( rf.isReadableFile() ) {
               this.cert = loadCertificate(rf.getFile().getAbsolutePath());
            } else {
                KeyPair pair = new KeyPair(this.publicKey,this.privateKey);
                if ( master ) {
                    this.cert=this.generateSelfSignedCert(pair, getDN());
                    String f = p.getProperty("certificate",base.getAbsolutePath()+"/cacerts.pem");
                    if ( this.cert != null ) {
                        this.storeCert(this.cert, f );
                    } else {
                        System.out.println("ERROR: could not generate root certificate");
                        System.exit(-1); 
                    }    
                } else {
                    if ( rootCA != null ) {
                        PKCS10CertificationRequest csr = this.generateCSR(pair, getDN(), null, null);
                        log(1, "is certificate request created ? "+((csr==null)?"No":"Yes"));
                        this.cert=rootCA.signCSR(csr);
                        log(1, "is certificate created ? "+((this.cert==null)?"No":"Yes->"+this.cert.getSubjectX500Principal().getName()));
                        if ( this.cert != null ) {
                            this.storeCert(this.cert, p.getProperty("certificate",base.getAbsolutePath()+"/cacerts.pem") );
                        } else {
                            System.out.println("ERROR: could not sign certificate request for CA : "+base.getAbsolutePath());
                            System.exit(-1);
                        }    
                    } else {
                        String f=p.getProperty("certificate",base.getAbsolutePath()+"/cacerts.pem").replaceAll(".pem$", ".csr");
                        rf=new ReadFile( f );
                        if ( rf.isReadableFile() ) {
                            System.out.println("INFO: let sign the certification request "+f+" from your CA");
                        } else {
                            PKCS10CertificationRequest csr = this.generateCSR(pair, getDN(), null, null);
                            this.storeCSR(csr, f);
                            System.out.println("INFO: let sign the certification request "+f+" from your CA");
                        } 
                        System.out.println("\tsave the certificate in "+p.getProperty("certificate",base.getAbsolutePath()+"/cacerts.pem"));
                        System.out.println("\ncomplete task - stop for now\n");
                        
                        System.exit(-1);
                    }
                }
            }            
        } else {
            throw new PKIConfigException("ERROR: CA Properties is NULL/Empty");
        }   
        
        
    }
    
    void checkSigning() {
        ReadDir reqDir = new ReadDir(this.BASEDIR.getAbsolutePath()+_FS+"req");
        
        log(1,"check CSR directory "+reqDir.getAbsolutePath()+" for new *.csr files");
        
        for ( String f: reqDir.getFiles(".csr$") ) {
            System.out.println("found CSR directory "+reqDir.getAbsolutePath()+" with "+f);
            ReadFile rf = new ReadFile(reqDir.getAbsolutePath()+_FS+f.replaceAll(".csr$", ".crt"));
            if ( rf.isReadableFile() ) {
                System.out.println("INFO: csr already handled - skip");
            } else {
                X509Certificate crt = this.signCSR( loadCSR(reqDir.getAbsolutePath()+_FS+f) );
                if ( crt != null ) {
                    this.storeCert(crt, rf.getFile().getAbsolutePath());
                    System.out.println("INFO: certificate is stored in "+rf.getFile().getAbsolutePath());
                } else {
                    System.out.println("ERROR: could not sign the certificate request - cancel request ");
                    (new WriteFile(reqDir.getAbsolutePath()+_FS+f)).move(new File(reqDir.getAbsolutePath()+_FS+f+".bad"));
                }
            }
        }
        
    }
}

