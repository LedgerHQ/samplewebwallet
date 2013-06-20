
// TODO OTO: still not consistent, all methods here shall not interact with UI, and take everything as parameters
// TODO OTO: return trusted inputs list so that we can 
// TODO OTO: how to pay with multiple input private keys to multiple outputs

        var timeout = null;
 
        function hidapiPluginLoaded() {
                terminalFactory = new HidapiPlugupCardTerminalFactory();
                pluginReady = true;
                $("#hidapiMessage").html("&nbsp;&nbsp;Plugin");
                rescan();
        }

        function rescan() {
                // uninit to ensure no desync
                tokenSerial = null;
          
                try {
                if (typeof terminalFactory == "undefined") {
                        return;
                }
                var readers = terminalFactory.list();
                if (readers.length == 0) {
                        $("#hidapiDevicePath").html("&nbsp;&nbsp;Not found");
                        return;
                }
                if (readers.length == 1) {
                        $("#hidapiDevicePath").html("&nbsp;&nbsp;" + readers[0].trim());
                }
                if (readers.length > 1) {
                        $("#hidapiDevicePath").html("&nbsp;&nbsp;" + readers[0].trim() + " (multiple devices found)");       
                }
                card = terminalFactory.getCardTerminal(readers[0]).getCard();
                plugup = new PlugupV2(card);
                bitcoin = new BitcoinBasic(card);
                deviceInfos = plugup.getDeviceInfos();
                wallet = [];
                
                // for brainwallet operation to have a unique key to store encrypted private keys related to the inserted dongle
                tokenSerial = deviceInfos['STSerial']+deviceInfos['STPIN']+deviceInfos['STDate'];
                
                $("#btchipVersion").html("&nbsp;&nbsp;" + deviceInfos['appVersion'].toString(HEX).trim());
                }
                catch (e) {
                  alert(e);
                }
        }
        
        function checkKey(value) {
                var key;
                try {
                        key = new ByteString(value, HEX);
                }
                catch(e) {
                        alert("Invalid key value " + value);
                        return;
                }
                if (key.length != 16) {
                        alert("Invalid key length for " + value);
                        return;
                }
                return key;
        }

        function checkVersion(value) {
                var result = parseInt(value, 16);
                if (typeof result != "number") {
                        alert("Invalid keyset version " + value);
                        return;
                }
                if ((result <= 0) || (result > 255)) {
                        alert("Invalid keyset version " + value);
                        return;
                }
            return result;
        }
        
        function openGP() { 
                try {
                                var securityLevel = 0;
                                if (typeof $("#GPCMAC").attr('checked') != "undefined") {
                                        securityLevel |= 0x01;
                                 }
                                 if (typeof $("#GPCENC").attr('checked') != "undefined") {
                                        securityLevel |= 0x02;
                                 }
                                 if (typeof $("#GPRMAC").attr('checked') != "undefined") {
                                        securityLevel |= 0x10;
                                 }
                                 if (typeof $("#GPRENC").attr('checked') != "undefined") {
                                        securityLevel |= 0x20;
                                 }

                 var encKey = checkKey($("#keysetGP1").val());
                 var macKey = checkKey($("#keysetGP2").val());
                 var dekKey = checkKey($("#keysetGP3").val());
                 var targetVersion = checkVersion($("#keysetGPVersion").val());

                                 var sam = new PlugupSAMSimu();
                                 var secureChannel = new SecureChannelSAM(sam);
                                 var secureChannelCard = new SecureChannelCard(card, secureChannel);
                                 secureChannelCard.setKeyset([encKey, macKey, dekKey]);
                                 secureChannelCard.openSession(securityLevel, targetVersion);
                                 sc = secureChannelCard;
                }
                catch(e) {
                        log.error(e);
                        alert("Error opening Secure Channel");
                }
        }
        
    function generateKeyResponse(kek, result, fresh, callback) {
        try {
                var publicKey = result[0];
                var privateKey = result[1];
                var diversifier = result[2];
                var proof = result[3];
                /*
                var base64Data = convertBase64(block);                  
                $("#genProof").html(create_qrcode("1" + base64Data, 10, 'L'));
                $("#genEncryptedPrivateKey").html("&nbsp;&nbsp;" + privateKey.toString(HEX));
                $("#genPublicKey").html("&nbsp;&nbsp;" + publicKey.toString(HEX));
                */
                
                var block = result[0].concat(result[1]).concat(result[2]).concat(result[3]);
                var keyObject = {};
                keyObject['kek'] = Convert.toHexByte(kek);
                keyObject['private'] = privateKey.toString(HEX);
                keyObject['public'] = publicKey.toString(HEX);
                var publicKeyNum = [];
                for (var i=0; i<publicKey.length; i++) {
                        publicKeyNum.push(publicKey.byteAt(i));
                }
                var addressHash = Crypto.RIPEMD160(Crypto.SHA256(publicKeyNum, {asBytes: true}), {asBytes: true});
                var hash160 = "";
                for (var i=0; i<addressHash.length; i++) {
                        hash160 += Convert.toHexByte(addressHash[i]);
                }
                keyObject['hash160'] = hash160;
                addressHash.unshift(0);
                var checksum = Crypto.SHA256(Crypto.SHA256(addressHash, {asBytes: true}), {asBytes: true});
                
                var bytes = addressHash.concat(checksum.slice(0,4));
                
                keyObject['address'] = Bitcoin.Base58.encode(bytes);
                keyObject['fresh'] = fresh;
                
                /*
                // Only import is not already in wallet
                var alreadyExists = false;
                for (var i=0; i<privateKeys.length; i++) {
                        if (privateKeys[i]['public'] == keyObject['public']) {
                                alreadyExists = true;
                                break;
                        }
                }
                if (!alreadyExists) {
                        privateKeys.push(keyObject);
                        $("#privateKeys").html(JSON.stringify(privateKeys));
                }
                */
                
                callback(keyObject);
        }
        catch(e) {
                log.error(e);
                alert("Error generating key");                                  
        }
    }
        
    function btchipGenerateKey(callback) {
        var kek = checkVersion($("#privateKeyKeyset").val());
        var proofKey = checkVersion($("#privateKeySignatureKeyset").val());
        if ((typeof kek == "undefined") || (typeof proofKey == "undefined")) {
                return;
        }
        $("#keyGenerationStatus").html("&nbsp;&nbsp;Start key generation");
        clearTimeout(timeout);
        timeout = setTimeout(function () {
          var start = new Date().getTime();
          try {
                  var result = bitcoin.generateKeypair(kek, proofKey);
                  delta = new Date().getTime() - start;                   
                  $("#keyGenerationStatus").html("&nbsp;&nbsp; key generation completed - " + delta + "ms");      
                  generateKeyResponse(kek, result, true, callback);
          }
          catch(e) {
                          log.error(e);
                          //alert("Error generating key");                  
                          //throw e;
          }
        }, 
        10);
    }
    
    function btchipImportWIF(key, callback) {
        var kek = checkVersion($("#privateKeyKeyset").val());
        var proofKey = checkVersion($("#privateKeySignatureKeyset").val());
        if ((typeof kek == "undefined") || (typeof proofKey == "undefined") || (key.length == 0)) {
                return;
        }
        $("#keyGenerationStatus").html("&nbsp;&nbsp;Start key import");
        clearTimeout(timeout);
        timeout = setTimeout(
          function () {
            var kek = checkVersion($("#privateKeyKeyset").val());
            var proofKey = checkVersion($("#privateKeySignatureKeyset").val());
            
            var start = new Date().getTime();
            try {                   
                    var result = bitcoin.generateKeypairFromData(kek, proofKey, new ByteString(key, ASCII), BitcoinBasic.KEY_PREPARE_FLAG_BASE58_ENCODED);
                    delta = new Date().getTime() - start;                   
                    $("#keyGenerationStatus").html("&nbsp;&nbsp; key import completed - " + delta + "ms");  
                    generateKeyResponse(kek, result, true, callback);
            }
            catch(e) {
                            log.error(e);
                            alert("Error generating key");                  
            }                       
          },
          10);
    }
    
    
    
    function btchipUpdateWallet(privencoded, transactions, unspents) {
        return bitcoin.updateWallet(privencoded, 
                                    checkVersion($("#trustedInputKeyset").val()), 
                                    transactions, 
                                    unspents,
                                    function(percentage) {
                                      //$('#txBalance').val('Loading ' + percentage*100 + "%...");
                                    });
/* unsupported
        return bitcoin.updateWalletBlockExplorer(privencoded, 
                                    checkVersion($("#trustedInputKeyset").val()), 
                                    unspent_outputs, 
                                    function(percentage) {
                                      //$('#txBalance').val('Loading ' + percentage*100 + "%...");
                                    });
*/
    }
    
    function getTrustedInputAmount(trustedInput) {
        var amountBytes = [];
        var amount = new ByteString(trustedInput, HEX).bytes(4 + 32 + 4, 8);
        for (var i=0; i<amount.length; i++) {
                amountBytes.push(amount.byteAt(amount.length - i - 1));
        }
        return BigInteger.fromByteArrayUnsigned(amountBytes);
    }

    
    function btchipComputeTransaction(privenc) {
        var kek = checkVersion($("#privateKeyKeyset").val());           
        var proofKey = checkVersion($("#privateKeySignatureKeyset").val());
        var trustedInputKeyset = checkVersion($("#trustedInputKeyset").val());
        
        // send the unspent onto the source
        var changeKey = privenc;
        
        var transactionAddress = $("#txDest").val();
        var transactionAmount = Bitcoin.Util.parseValue($("#txValue").val());
        var transactionFees = Bitcoin.Util.parseValue($("#txFee").val());
        // Sanity checks
        var walletAmount = BigInteger.ZERO;
        for (var i=0; i<wallet.length; i++) {
                walletAmount = walletAmount.add(getTrustedInputAmount(wallet[i]['trustedInput']))
        }
        if (transactionAmount.compareTo(BigInteger.ZERO) == 0) {
                alert("Cannot send null transaction");
                return;
        }
        var totalAmount = transactionAmount.add(transactionFees);
        if (totalAmount.compareTo(walletAmount) > 0) {
                alert("Not enough funds");
                return;
        }
        
        // Check which inputs join the transaction
        var sortedWallet = wallet.slice(0);
        sortedWallet.sort(function(a, b) { 
                return getTrustedInputAmount(a['trustedInput']).compareTo(getTrustedInputAmount(b['trustedInput']));
        });
        var subtotal = BigInteger.ZERO;
        var usedInputs = 0;
        var transactionInputs = [];
        while (subtotal.compareTo(totalAmount) < 0) {
                log.debug("Using " + sortedWallet[usedInputs]['amount'] + " " + sortedWallet[usedInputs]['trustedInput']);
                subtotal = subtotal.add(getTrustedInputAmount(sortedWallet[usedInputs]['trustedInput']));
                transactionInputs.push(sortedWallet[usedInputs]);               
                usedInputs++;
        }
        
        // Pair each input with its key
        var pairedKeys = [];
        var currentHash;
        for (var i=0; i<usedInputs; i++) {
                currentHash = new ByteString(sortedWallet[i]['outputScript'], HEX).bytes(3, 0x14).toString(HEX);
                //var keyFound = false;
                //for (var j=0; j<privateKeys.length; j++) {
                //        if (privateKeys[j]['hash160'] == currentHash) {
                                var currentPairedKey = [];
                                currentPairedKey.push(new ByteString(privenc['public'], HEX));
                                currentPairedKey.push(new ByteString(privenc['private'], HEX));
                                currentPairedKey.push(privenc['kek']);
                                pairedKeys.push(currentPairedKey);
                                //keyFound = true;
                                //break;
                //        }
                //}
                //if (!keyFound) {
                //        alert("Private key missing for hash " + currentHash);
                //        return;
                //}
        }        
        
        /* use the same as source
        // Compute the change key if needed
        if (subtotal.compareTo(totalAmount) != 0) {
            log.debug("Creating change address");
            
            changeKey = bitcoin.generateKeypair(kek, proofKey);
            generateKeyResponse(kek, changeKey, false);
        }
        */

        // Compute the transaction
        // TODO : different keyset for each trusted input
        log.debug("Computing transaction");
        var result = bitcoin.createPaymentTransaction(transactionInputs,
                                                      pairedKeys,
                                                      0x0001, 
                                                      trustedInputKeyset, 
                                                      kek, 
                                                      new ByteString(changeKey['private'], HEX), // TODO : add transaction control reference
                                                      new ByteString(transactionAddress, ASCII),
                                                      bitcoin.amountStringToBytestring($("#txValue").val()),
                                                      bitcoin.amountStringToBytestring($("#txFee").val())   
                         );
        //$("#computedTransaction").html(result.toString(HEX));
        return result.toString(HEX);
    }
    
    
