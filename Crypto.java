//Frances Astorian
//June 5 2020
import java.util.*;
import java.math.*;
import java.io.*;
import java.security.*;
import java.text.*;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.Key;
import java.nio.file.*;

public class Crypto {

    /**
     * Create the genesis block 
     * This is the initial block in the block chain, and the block should always be the same
     */
    public static void createGenesis() throws Exception{
        String block_0 = "This is the initial block in the block chain.";
        FileWriter gen = new FileWriter("block_0.txt");
            gen.write(block_0);
            gen.close();
        System.out.println("Genesis block created in block_0.txt");
    }

    /**
     * Generate a wallet
     * This will create RSA public/private key set (1024 bit keys)
     */
    public static void generateKeys(String filename) throws Exception{
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair pair = keyGen.generateKeyPair();
        Key priKey = pair.getPrivate();
        Key pubKey = pair.getPublic();

        // This will write the public/private key pair to a file in text
        // format.  It is adapted from the code from
        // https://snipplr.com/view/18368/saveload--private-and-public-key-tofrom-a-file/
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(pubKey.getEncoded());
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(priKey.getEncoded());
        PrintWriter fout = new PrintWriter(new FileOutputStream(filename));
        //fout.println("Public Key:");
        fout.println(getHexString(x509EncodedKeySpec.getEncoded()));
        //fout.println("Private Key");
        fout.println(getHexString(pkcs8EncodedKeySpec.getEncoded()));
        fout.println();
        fout.close();
        System.out.println("New wallet created in " +filename+ " with wallet tag "+getAddress(filename));
    }

    /**
     * Converts an array of bytes into a hexadecimal number in text format
     */
    static String getHexString(byte[] b) {
        String result = "";
        for (int i = 0; i < b.length; i++) {
            int val = b[i];
            if ( val < 0 )
            val += 256;
            if ( val <= 0xf )
            result += "0";
            result += Integer.toString(val, 16);
        }
        return result;
    }
    
    /**
     * Get wallet tag
     * This will print out the tag of the public key for a given wallet, which is the hash of the public key
     */
    static String getAddress(String filename) throws Exception{
        BufferedReader br = new BufferedReader(new FileReader(filename));
        String first = br.readLine();
        String stPubKey = br.readLine();
        //System.out.println(stPubKey);
        byte[] barr = stPubKey.getBytes();
        MessageDigest mD = MessageDigest.getInstance("SHA-256");
        String hash = convertHash(mD.digest(barr));
        
        return hash.substring(0,16);
    }

    /**
     * Converts hash byte to string representation of hash
     */
    static String convertHash (byte hash[]) {
        int hashSize = 0;
        try {
            hashSize = MessageDigest.getInstance("SHA-256").getDigestLength() * 2;
        } catch (Exception e) {
            System.out.println ("Your Java installation does not support the SHA-256 hashing method; change that in RSA.java to continue.");
            System.exit(1);
        }
        char chash[] = new char[hashSize];
        for ( int i = 0; i < hashSize/2; i++ ) {
            int hashValue = hash[i];
            if ( hashValue < 0 )
                hashValue += 256;
            if ( hashValue/16 < 10 )
                chash[2*i] = (char) ('0' + hashValue/16);
            else
                chash[2*i] = (char) ('a' + hashValue/16 - 10);
            if ( hashValue%16 < 10 )
                chash[2*i+1] = (char) ('0' + hashValue%16);
            else
                chash[2*i+1] = (char) ('a' + hashValue%16 - 10);
        }
        return new String(chash);
    }

    /**
     * Fund wallets
     * This allows us to add as much money as we want to a wallet
     */
    static void fund(String address, String amt, String dest)throws Exception{

        FileWriter tran = new FileWriter(dest);
            tran.write("From: BANK\n");
            tran.write("To: "+address+"\n");
            tran.write("Amount "+amt+"\n");
            String timeStamp = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss").format(new java.util.Date());
            tran.write("Date: "+timeStamp+"\n");
            tran.close();
            System.out.println(address + " wallet was funded with "+amt+" CryptoDollars on "+timeStamp+". Transaction statement in "+dest);
            
    }

    /**
     * Signs transfer statement with encypted private Key 
     */
    public static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes());
    
        byte[] signature = privateSignature.sign();
    
        return Base64.getEncoder().encodeToString(signature);
    }

    static KeyPair LoadKeyPair(String filename) throws Exception {
        // Read wallet
        Scanner sin = new Scanner(new File(filename));
        byte[] encodedPublicKey = getByteArray(sin.next());
        byte[] encodedPrivateKey = getByteArray(sin.next());
        sin.close();
        // Generate KeyPair.
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        return new KeyPair(publicKey, privateKey);
    }
   
    static byte[] getByteArray(String hexstring) {
        byte[] ret = new byte[hexstring.length()/2];
        for (int i = 0; i < hexstring.length(); i += 2) {
            String hex = hexstring.substring(i,i+2);
            if ( hex.equals("") )
            continue;
            ret[i/2] = (byte) Integer.parseInt(hex,16);
        }
        return ret;
    }

    /**
     * Transfer funds
     * This is how payments are made
     * Will be provided with four additional command line parameters: the source wallet file name, the destination wallet address, the amount to transfer, and the file name to save the transaction statement to
     */
    static void transfer(String sourceFile, String destAddr, String amt, String tran)throws Exception{

        FileWriter trans = new FileWriter(tran);
            //trans.write("From: "+ getAddress(sourceFile)+"\n");
            //trans.write("To: "+destAddr+"\n");
            //trans.write("Amount: "+amt+"\n");
        String timeStamp = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss").format(new java.util.Date());
            //trans.write("Date: "+timeStamp+"\n");
           // trans.close();

        String toHash = "From: "+getAddress(sourceFile)+"\nTo: "+destAddr+"\nAmount: "+amt+"\nDate: "+timeStamp+"\n";
        trans.write(toHash);
        KeyPair keys = LoadKeyPair(sourceFile);
        trans.write(sign(toHash, keys.getPrivate()));
        trans.close();

        System.out.println(getAddress(sourceFile) + " transferred "+ amt+" CryptoDollars to "+destAddr+" on "+timeStamp+". Transaction statement in "+tran);
    }

    /**
     * Check a balance
     * Based on the transactions in the block chain and also in the ledger, compute the balance for the provided wallet.
     */
    static double balance(String addr) throws Exception{
        double balance = 0;
        if(Files.exists(Paths.get("ledger.txt"))){
            BufferedReader led = new BufferedReader(new FileReader("ledger.txt"));
            String line="";
            while((line=led.readLine())!=null&&line.length()!=0){
                String [] arr = line.split(" ");
                if(arr[4].equals(addr)){
                    balance+= Float.parseFloat(arr[2]);
                }
                if(arr[0].equals(addr)){
                    balance-= Float.parseFloat(arr[2]);
                }
            }
            led.close();
        }
        
        int n = 0;
        while(Files.exists(Paths.get("block_"+n+".txt"))){
            BufferedReader b = new BufferedReader(new FileReader("block_"+n+".txt"));
            String line1="";
            while((line1=b.readLine())!=null&&line1.length()!=0){
                String [] arr = line1.split(" ");

                if(arr.length > 6 && arr[4].equals(addr)){
                    balance+= Float.parseFloat(arr[2]);
                }
                if(arr.length>6&&arr[0].equals(addr)){
                    balance-=Float.parseFloat(arr[2]);
                }
            }
            n++;
        }
        
        System.out.println("Available balance for wallet "+addr+ " is: " + balance);
        return balance;
    }

    /**
     * Verifies the signature
     */
    public static boolean v(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes());
    
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
    
        return publicSignature.verify(signatureBytes);
    }

    /**
     * Verify a transaction
     * Verify that a given transaction statement is valid, which will require checking the signature and the availability of funds.
     */
    static void verify(String filename, String trans)throws Exception{
        
        FileInputStream fstream = new FileInputStream(trans);
        BufferedReader t = new BufferedReader(new InputStreamReader(fstream));
       // BufferedReader t = new BufferedReader(new FileReader(trans));
   
        String from = t.readLine();
        //System.out.println(from);
        String to = t.readLine();
        String amt = t.readLine();
        String date = t.readLine();
        String text=from+"\n"+to+"\n"+amt+"\n"+date+"\n";
        String sig = t.readLine();
        t.close();
        if(from.equals("From: BANK")){
            FileWriter fw = new FileWriter("ledger.txt", true);
            fw.write(from.substring(6)+" transferred "+amt.substring(7)+ " to "+to.substring(4)+" on "+date.substring(6)+"\n");
            fw.close();
            System.out.println("Transaction funded by BANK so is valid and was added to ledger.txt.");
        }else{
            try{
                KeyPair keys = LoadKeyPair(filename);
                String[] arr = amt.split(" ");
                double m = Double.parseDouble(arr[1]);
                
                String addr = getAddress(filename);
        
        
                if(v(text,sig,keys.getPublic())&&balance(addr)>=m){
                    FileWriter fw = new FileWriter("ledger.txt", true);
                    fw.write(from.substring(6)+" transferred "+amt.substring(8)+ " to "+to.substring(4)+" on "+date.substring(6)+"\n");
                    fw.close();
                    System.out.println("Transaction in "+filename+" is valid and was moved to ledger.txt");
                }else if(!v(text,sig,keys.getPublic())){
                    System.out.println("Signatures don't matchTransaction in "+filename+" not valid.");
                }else if(balance(addr)<m){
                    System.out.println("Insufficient funds! Transaction in "+filename+" not valid.");
                }
            }
        catch(Exception e){
            System.out.println("key error");
        }
           
        }
        
    }

    /**
     * Create, mine, and sign block
     * This will form another block in the blockchain.
     * The ledger will be emptied of transaction records, as they will all go into the current block being computed. 
     * A nonce will have to be computed to ensure the hash is below a given value
     */
    static void mine(String diff)throws Exception{
        int n = 1;
        while(Files.exists(Paths.get("block_"+n+".txt"))){
            n++;
        }
        FileWriter fw = new FileWriter("block_"+n+".txt");
        //fw.write(getHashOfFile("block_"+n-1+".txt"));
        n--;
        String toFile = getHashOfFile("block_"+n+".txt")+"\n\n";
        BufferedReader l = new BufferedReader(new FileReader("ledger.txt")); 
        //System.out.println();
        String line;
        while((line=l.readLine())!=null&&line.length()!=0){
            //fw.write(line);
            toFile=toFile+ line+"\n";
        }
        //System.out.println(toFile);
        boolean found = false;
        int nonce = 0;
        String tocheck = "";
        for(int i = 0; i<Integer.parseInt(diff);i++){
            tocheck+="0";
        }
        while(found == false){
            byte[] barr = (toFile+"\nnonce: "+nonce).getBytes();
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String hash = convertHash(digest.digest(barr));
            if(hash.substring(0,Integer.parseInt(diff)).equals(tocheck)){
                //System.out.println("nonce: "+nonce);
                fw.write(toFile+"\nnonce: "+nonce);
                found=true;
                fw.close();
                System.out.println("Ledger transaction moved to block_"+(n+1)+".txt and mined with difficulty " +diff+" and nonce "+nonce);
            }
            nonce++;
        }
        File file = new File("ledger.txt");
        file.delete();
        l.close();

    }

    static String getHashOfFile(String filename) throws Exception {
        byte[] filebytes = Files.readAllBytes(Paths.get(filename));
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedHash = digest.digest(filebytes);
        return getHexString(encodedHash);
        }

    /**
     * Validate the blockchain
     * This should go through the entire block chain, validating each one.  
     * */    
    static void validate()throws Exception{
        int n = 1;
        while(Files.exists(Paths.get("block_"+n+".txt"))){
            BufferedReader l = new BufferedReader(new FileReader("block_"+n+".txt")); 
            String hash = l.readLine();
            int p = n-1;
            if(!hash.equals(getHashOfFile("block_"+p+".txt"))){
                System.out.println("Error in validation. Hashes of blockchains incorrect.");
            }
            n++;
        }
        System.out.println("Entire blockchain is valid.");
    }

    public static void main (String[] args){
        //System.out.println(args.length);
        if(args[0].equals("genesis")){
           try{ createGenesis(); }
           catch(Exception e){
               System.out.println("Exception occured in Geneis step.");
           }
        }else if(args[0].equals("generate")){
            try{generateKeys(args[1]);}
            catch(Exception e){
                System.out.println("Exception occured in Key Generation step.");
            }
        }else if(args[0].equals("address")){
            try{System.out.println(getAddress(args[1]));}
            catch(Exception e){
                System.out.println("Exception occured in Address step.");
            }
        }else if(args[0].equals("fund")){
            try{fund(args[1], args[2], args[3]);}
            catch(Exception e){
                System.out.println("Exception occured in Fund step.");
            }
        }else if(args[0].equals("transfer")){
            try{transfer(args[1], args[2], args[3], args[4]);}
            catch(Exception e){
                System.out.println("Exception occured in Transfer step.");
            }
        }else if(args[0].equals("balance")){
            try{ balance(args[1]);}
            catch(Exception e){
                System.out.println("Exception occured in Balance step.");
            }
        }else if(args[0].equals("verify")){
            try{verify(args[1], args[2]);}
            catch(Exception e){
                System.out.println("Exception occured in Verify step.");
            }
        }else if(args[0].equals("mine")){
            try{mine(args[1]);}
            catch(Exception e){
                System.out.println("Exception occured in Mining step.");
            }
        }else if(args[0].equals("validate")){
            try{validate();}
            catch(Exception e){
                System.out.println("Exception occured in Validate step.");
            }
        }
    }
}